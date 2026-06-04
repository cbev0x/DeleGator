"""
modules/enumerate.py

Delegation enumeration module for DeleGator.

Orchestrates all LDAP queries and correlates findings into:
  - Unconstrained delegation targets with coercion potential
  - Constrained delegation accounts with protocol transition status
  - RBCD write paths available to the current user
  - Attack path chains combining multiple findings

This is the primary module called by `delegator.py enum`.

OPSEC profile:
  Full enumeration (--all):
    Events: 4662 x6-12, 4769 x0, 4768 x0-1 (if not using ccache)
    Noise: MEDIUM
    Notes: All queries use targeted LDAP filters. No directory dumps.

  Targeted enumeration (single type):
    Events: 4662 x2-4
    Noise: LOW
"""

import sys
import socket
import struct
from typing import Optional
from dataclasses import dataclass, field

from core.auth import AuthContext
from core.ldap import LDAPConnection, OpsecConfig, connect
from utils.output import (
    info, success, warning, error, section, divider,
    print_unconstrained_table, print_constrained_table,
    print_rbcd_table, print_attack_paths,
    print_json, build_json_output, is_json_mode,
)
from utils.opsec import OpsecCheck, NoiseLevel, print_operation_noise


# ---------------------------------------------------------------------------
# EnumConfig — controls what gets enumerated
# ---------------------------------------------------------------------------

@dataclass
class EnumConfig:
    """
    Controls which enumeration queries run and how results are presented.

    all_types:       Run all three enumeration types
    unconstrained:   Enumerate unconstrained delegation
    constrained:     Enumerate constrained delegation
    rbcd:            Enumerate RBCD write paths
    check_reachable: Ping-check each unconstrained target
    json_out:        Emit JSON instead of human-readable output
    opsec_check:     Prompt before noisy operations
    delay_ms:        Inter-query delay in milliseconds
    jitter_pct:      Jitter percentage for delay
    slow:            Enable slow preset (2000ms + 30% jitter)
    search_base:     Restrict queries to a specific OU/base DN
    dc_ip:           Domain controller IP
    domain:          Domain FQDN
    output_dir:      Directory for any written output files
    """
    dc_ip:           str
    domain:          str
    all_types:       bool = True
    unconstrained:   bool = False
    constrained:     bool = False
    rbcd:            bool = False
    check_reachable: bool = True
    json_out:        bool = False
    opsec_check:     bool = False
    delay_ms:        int  = 0
    jitter_pct:      int  = 0
    slow:            bool = False
    search_base:     Optional[str] = None
    output_dir:      str = "/tmp"


# ---------------------------------------------------------------------------
# EnumResult — structured output of the full enumeration
# ---------------------------------------------------------------------------

@dataclass
class EnumResult:
    """
    Aggregated results from a full enumeration run.
    Passed to output functions and returned to the caller.
    """
    unconstrained:  list[dict] = field(default_factory=list)
    constrained:    list[dict] = field(default_factory=list)
    rbcd_paths:     list[dict] = field(default_factory=list)
    attack_paths:   list[dict] = field(default_factory=list)
    domain_info:    dict       = field(default_factory=dict)

    @property
    def total_findings(self) -> int:
        return (
            len(self.unconstrained) +
            len(self.constrained) +
            len(self.rbcd_paths)
        )

    @property
    def critical_paths(self) -> list[dict]:
        return [
            p for p in self.attack_paths
            if p.get("severity", "").upper() == "CRITICAL"
        ]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_reachable(host: str, port: int = 445, timeout: float = 1.0) -> bool:
    """
    Quick TCP reachability check against port 445 (SMB).
    Used to flag unconstrained targets as live or dead.
    Fails silently — unreachable just means unknown, not an error.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # Strip the trailing $ from computer account names
        hostname = host.rstrip("$")
        result = sock.connect_ex((hostname, port))
        sock.close()
        return result == 0
    except (socket.error, OSError):
        return False


def _check_spooler_potential(hostname: str) -> list[str]:
    """
    Check which coercion techniques may be viable against a host
    by testing relevant ports and services.

    SpoolSS (PrinterBug): port 445 (SMB) must be reachable
    PetitPotam: port 445 reachable, may also check for EFSRPC
    DFSCoerce: port 445

    This is a lightweight check — actual coercion viability
    depends on patch level which we can't determine here.
    """
    coercible = []
    hostname_clean = hostname.rstrip("$")

    smb_reachable = _is_reachable(hostname_clean, 445)

    if smb_reachable:
        coercible.append("SpoolSS")
        coercible.append("PetitPotam")
        coercible.append("DFSCoerce")

    return coercible


def _uac_has_flag(uac_value, flag: int) -> bool:
    """Test a specific UAC bit flag."""
    try:
        return bool(int(uac_value) & flag) if uac_value else False
    except (TypeError, ValueError):
        return False


def _format_last_logon(timestamp) -> str:
    """
    Convert a Windows FILETIME or ldap3 datetime to a readable string.
    Returns 'Never' for null/zero values.
    """
    if not timestamp:
        return "Never"
    try:
        # ldap3 returns datetime objects for generalisedTime attributes
        if hasattr(timestamp, "strftime"):
            return timestamp.strftime("%Y-%m-%d")
        # Some attributes return the raw integer FILETIME
        filetime = int(timestamp)
        if filetime == 0:
            return "Never"
        # Convert Windows FILETIME (100-ns intervals since 1601) to Unix
        unix_ts = (filetime - 116444736000000000) // 10000000
        import datetime
        return datetime.datetime.utcfromtimestamp(unix_ts).strftime("%Y-%m-%d")
    except Exception:
        return str(timestamp)[:10] if timestamp else "Unknown"


def _parse_security_descriptor(sd_bytes: bytes) -> list[str]:
    """
    Minimal security descriptor parser to extract ACE subjects
    with write-class permissions over a computer object.

    Looks for these access rights that enable RBCD configuration:
      0x00000020 — WriteProperty (generic write to properties)
      0x00040000 — WriteDacl
      0x00080000 — WriteOwner
      0x10000000 — GenericAll
      0x00000004 — GenericWrite (maps to WriteProperty in AD context)

    Returns a list of SID strings that have write access.
    This is a best-effort parser — complex ACL inheritance is not
    fully resolved here. ACE subjects are returned for the
    enumeration module to cross-reference against known accounts.
    """
    WRITE_FLAGS = (
        0x00000020 |  # WriteProperty
        0x00040000 |  # WriteDacl
        0x00080000 |  # WriteOwner
        0x10000000 |  # GenericAll
        0x00000004    # GenericWrite
    )

    if not sd_bytes or len(sd_bytes) < 20:
        return []

    writers = []

    try:
        # SECURITY_DESCRIPTOR header is 20 bytes
        # Offset 16 = DACL offset (4 bytes, little-endian)
        dacl_offset = struct.unpack_from("<I", sd_bytes, 16)[0]

        if dacl_offset == 0 or dacl_offset >= len(sd_bytes):
            return []

        # ACL header: revision(1) + sbz1(1) + size(2) + ace_count(2) + sbz2(2)
        ace_count = struct.unpack_from("<H", sd_bytes, dacl_offset + 4)[0]
        pos = dacl_offset + 8  # Start of first ACE

        for _ in range(ace_count):
            if pos + 8 > len(sd_bytes):
                break

            # ACE header: type(1) + flags(1) + size(2)
            ace_type  = sd_bytes[pos]
            ace_size  = struct.unpack_from("<H", sd_bytes, pos + 2)[0]

            # Only process ACCESS_ALLOWED_ACE (type 0x00)
            if ace_type == 0x00 and pos + 8 <= len(sd_bytes):
                # ACCESS_ALLOWED_ACE: header(4) + mask(4) + SID
                access_mask = struct.unpack_from("<I", sd_bytes, pos + 4)[0]

                if access_mask & WRITE_FLAGS:
                    # Parse the SID starting at pos + 8
                    sid_str = _parse_sid(sd_bytes, pos + 8)
                    if sid_str:
                        writers.append(sid_str)

            pos += ace_size if ace_size > 0 else 4

    except (struct.error, IndexError):
        pass

    return list(set(writers))


def _parse_sid(data: bytes, offset: int) -> Optional[str]:
    """
    Parse a Windows SID from binary data at the given offset.
    Returns the SID string (S-1-5-...) or None on failure.
    """
    try:
        if offset + 8 > len(data):
            return None

        revision       = data[offset]
        sub_auth_count = data[offset + 1]
        # Identifier authority is 6 bytes big-endian
        authority      = int.from_bytes(data[offset + 2:offset + 8], "big")

        sub_auths = []
        for i in range(sub_auth_count):
            sub_offset = offset + 8 + (i * 4)
            if sub_offset + 4 > len(data):
                break
            sub_auth = struct.unpack_from("<I", data, sub_offset)[0]
            sub_auths.append(str(sub_auth))

        if not sub_auths:
            return None

        return f"S-{revision}-{authority}-" + "-".join(sub_auths)

    except (struct.error, IndexError):
        return None


def _sid_to_samname(sid: str, ldap_conn: LDAPConnection) -> Optional[str]:
    """
    Resolve a SID string to a sAMAccountName via LDAP.
    Used to make ACL output human-readable.
    """
    try:
        results = ldap_conn._query(
            f"(objectSid={sid})",
            ["sAMAccountName"],
        )
        if results:
            return results[0].get("sAMAccountName")
    except Exception:
        pass
    return None


def _is_high_value_spn(spns) -> bool:
    """
    Check if any delegatable SPN targets a high-value service.
    High-value = delegation to a service on a DC or critical server.
    """
    high_value_keywords = [
        "ldap/", "cifs/", "host/", "krbtgt",
        "mssqlsvc/", "gc/", "e3514235",
    ]
    if not spns:
        return False

    spn_list = spns if isinstance(spns, list) else [spns]

    for spn in spn_list:
        spn_lower = str(spn).lower()
        for keyword in high_value_keywords:
            if keyword in spn_lower:
                return True
    return False


# ---------------------------------------------------------------------------
# Attack path correlation
# ---------------------------------------------------------------------------

def _correlate_attack_paths(
    unconstrained: list[dict],
    constrained:   list[dict],
    rbcd_paths:    list[dict],
    current_user:  str,
    domain:        str,
) -> list[dict]:
    """
    Correlate individual findings into actionable attack chains.

    This is what separates DeleGator from a script that just dumps
    delegation attributes — it connects the dots between findings
    to surface complete exploitation paths the operator can act on.

    Attack paths are ordered by severity (CRITICAL first).
    """
    paths = []

    # RBCD paths where current user can write
    for entry in rbcd_paths:
        if not entry.get("_current_user_writable"):
            continue

        target   = entry.get("sAMAccountName", "?")
        write_by = entry.get("_writable_by", current_user)

        # Check if the RBCD target has interesting delegation of its own
        # (chained delegation path)
        target_constrained = next(
            (c for c in constrained
             if c.get("sAMAccountName", "").rstrip("$").lower()
             == target.rstrip("$").lower()),
            None
        )

        if target_constrained:
            delegate_spns = target_constrained.get("msDS-AllowedToDelegateTo", [])
            spn_str = (
                delegate_spns[0] if isinstance(delegate_spns, list)
                else str(delegate_spns)
            )
            paths.append({
                "severity":    "CRITICAL",
                "description": (
                    f"{write_by} has write access over {target} "
                    f"which can delegate to {spn_str}"
                ),
                "steps": [
                    f"Configure RBCD on {target} "
                    f"(writes msDS-AllowedToActOnBehalfOfOtherIdentity)",
                    f"S4U2Self as {write_by} — obtain forwardable ticket "
                    f"as impersonated user",
                    f"S4U2Proxy to {spn_str}",
                    "Write ccache → use with Impacket or NetExec",
                ],
                "type": "rbcd_chain",
            })
        else:
            paths.append({
                "severity":    "CRITICAL",
                "description": (
                    f"{write_by} has write access over {target} "
                    f"— RBCD exploitation path available"
                ),
                "steps": [
                    f"Configure RBCD on {target}",
                    "S4U2Self → S4U2Proxy chain",
                    "Impersonate privileged user against target service",
                    "Write ccache → use with Impacket or NetExec",
                ],
                "type": "rbcd",
            })

    # Unconstrained delegation + coercion paths
    for entry in unconstrained:
        if not entry.get("_reachable"):
            continue

        target    = entry.get("sAMAccountName", "?")
        coercible = entry.get("_coercible", [])

        if coercible:
            coerce_method = coercible[0]
            paths.append({
                "severity":    "HIGH",
                "description": (
                    f"Coerce {target} via {coerce_method} "
                    f"→ capture TGT → potential DCSync or lateral movement"
                ),
                "steps": [
                    f"Set up Responder or krbrelayx listener",
                    f"Coerce {target} using {coerce_method}",
                    "Capture forwarded TGT from unconstrained delegation",
                    "Use TGT for DCSync or further impersonation",
                ],
                "type": "unconstrained_coerce",
            })

    # Constrained delegation with protocol transition (most exploitable)
    for entry in constrained:
        uac        = entry.get("userAccountControl") or 0
        proto_trans = _uac_has_flag(uac, 16777216)

        if not proto_trans:
            continue

        account = entry.get("sAMAccountName", "?")
        spns    = entry.get("msDS-AllowedToDelegateTo", [])
        spn_str = (spns[0] if isinstance(spns, list) and spns else str(spns))

        high_value = _is_high_value_spn(spns)

        paths.append({
            "severity":    "HIGH" if high_value else "MEDIUM",
            "description": (
                f"{account} has constrained delegation with protocol "
                f"transition to {spn_str}"
            ),
            "steps": [
                f"Authenticate as or compromise {account}",
                "S4U2Self → obtain forwardable ticket for any user",
                f"S4U2Proxy → {spn_str}",
                "Write ccache → use with Impacket or NetExec",
            ],
            "type": "constrained_proto_transition",
        })

    # Sort: CRITICAL first, then HIGH, then MEDIUM
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    paths.sort(key=lambda p: severity_order.get(p.get("severity", "MEDIUM"), 2))

    return paths


# ---------------------------------------------------------------------------
# Core enumeration functions
# ---------------------------------------------------------------------------

def enumerate_unconstrained(
    ldap_conn:    LDAPConnection,
    opsec:        OpsecCheck,
    check_reach:  bool = True,
) -> list[dict]:
    """
    Enumerate computers with unconstrained delegation configured.
    Excludes domain controllers to eliminate false positives.
    Optionally checks reachability and coercion potential.
    """
    if not opsec.check("ldap_enum_targeted"):
        return []

    info("Querying unconstrained delegation (excluding DCs)...")
    results = ldap_conn.get_unconstrained_computers()

    if not results:
        return []

    enriched = []
    for entry in results:
        samname = str(entry.get("sAMAccountName", "")).rstrip("$")

        if check_reach:
            reachable = _is_reachable(samname)
            coercible = _check_spooler_potential(samname) if reachable else []
        else:
            reachable = None
            coercible = []

        last_logon_raw = entry.get("lastLogonTimestamp")
        entry["_reachable"]  = reachable
        entry["_coercible"]  = coercible
        entry["_last_logon"] = _format_last_logon(last_logon_raw)

        enriched.append(entry)

    success(f"Found {len(enriched)} unconstrained delegation target(s)")
    return enriched


def enumerate_constrained(
    ldap_conn: LDAPConnection,
    opsec:     OpsecCheck,
) -> list[dict]:
    """
    Enumerate accounts with constrained delegation.
    Differentiates protocol transition vs non-transition variants
    since exploitation paths differ significantly between them.
    """
    if not opsec.check("ldap_enum_targeted"):
        return []

    info("Querying constrained delegation accounts...")
    results = ldap_conn.get_constrained_accounts()

    if not results:
        return []

    enriched = []
    for entry in results:
        uac        = entry.get("userAccountControl") or 0
        proto_trans = _uac_has_flag(uac, 16777216)
        spns       = entry.get("msDS-AllowedToDelegateTo")
        high_value = _is_high_value_spn(spns)

        entry["_proto_transition"] = proto_trans
        entry["_high_value"]       = high_value

        enriched.append(entry)

    proto_count = sum(1 for e in enriched if e.get("_proto_transition"))
    success(
        f"Found {len(enriched)} constrained delegation account(s) "
        f"({proto_count} with protocol transition)"
    )
    return enriched


def enumerate_rbcd_paths(
    ldap_conn:    LDAPConnection,
    opsec:        OpsecCheck,
    auth:         AuthContext,
) -> list[dict]:
    """
    Enumerate RBCD write paths available to the current user.

    Queries computer objects with nTSecurityDescriptor using the
    LDAP SD control, parses ACLs, and checks both direct SID matches
    and inherited group membership — catching permissions granted
    via group membership rather than direct ACEs.

    Searches the full domain base to catch machines in custom OUs.
    """
    if not opsec.check("ldap_enum_targeted"):
        return []

    info("Querying computer object ACLs for RBCD write paths...")
    info("(Searching full domain — use --search-base to scope if needed)")

    # Resolve current user's SID and all group memberships
    current_sid, group_dns = ldap_conn.get_account_sid_and_groups(auth.username)
    if not current_sid:
        warning(f"Could not resolve SID for '{auth.username}' — write path check limited")

    # Build a flat set of all SIDs we should treat as "current user"
    # This includes direct SID + all group SIDs the user is member of
    user_sids: set[str] = set()
    if current_sid:
        user_sids.add(current_sid)

    # Resolve group SIDs recursively
    if group_dns:
        info(f"Resolving {len(group_dns)} group membership(s) for write path check...")
        for group_dn in group_dns:
            # Get the group's own SID
            group_results = ldap_conn._query(
                f"(distinguishedName={group_dn})",
                ["objectSid", "sAMAccountName"],
            )
            if group_results and group_results[0].get("objectSid"):
                user_sids.add(str(group_results[0]["objectSid"]))
            # Also recursively get all member SIDs of this group
            member_sids = ldap_conn.get_group_members_recursive(group_dn)
            user_sids.update(member_sids)

    # Get all computer objects with security descriptors
    computers = ldap_conn.get_computers_writable_by(current_sid or "")

    if not computers:
        info("No computer objects returned — check permissions allow SD reads")
        return []

    sd_count = sum(1 for c in computers if c.get("nTSecurityDescriptor"))
    info(f"Retrieved {len(computers)} computer objects, {sd_count} with security descriptors")

    rbcd_paths = []

    for computer in computers:
        sd_raw  = computer.get("nTSecurityDescriptor")
        samname = computer.get("sAMAccountName", "?")

        if not sd_raw:
            continue

        if isinstance(sd_raw, bytes):
            writer_sids = _parse_security_descriptor(sd_raw)
        else:
            continue

        if not writer_sids:
            continue

        for sid in writer_sids:
            if _is_privileged_sid(sid):
                continue

            # Check if this SID matches the current user directly
            # OR matches any group the user is a member of
            current_user_writable = sid in user_sids

            samname_writer = _sid_to_samname(sid, ldap_conn)
            display_writer = samname_writer or sid

            rbcd_paths.append({
                "sAMAccountName":           samname,
                "distinguishedName":        computer.get("distinguishedName"),
                "_writable_by":             display_writer,
                "_writer_sid":              sid,
                "_current_user_writable":   current_user_writable,
                "_risk": (
                    "CRITICAL" if current_user_writable else "HIGH"
                ),
            })

    # Deduplicate by computer — if multiple ACEs make it writable
    # keep only the highest risk one per target
    seen = {}
    for path in rbcd_paths:
        key = path["sAMAccountName"]
        if key not in seen or path["_current_user_writable"]:
            seen[key] = path
    rbcd_paths = list(seen.values())

    if rbcd_paths:
        direct = sum(1 for p in rbcd_paths if p.get("_current_user_writable"))
        success(
            f"Found {len(rbcd_paths)} RBCD write path(s) "
            f"({direct} directly exploitable by current user)"
        )
    else:
        info("No non-privileged RBCD write paths identified")

    return rbcd_paths


def _is_privileged_sid(sid: str) -> bool:
    """
    Return True for well-known privileged SIDs that legitimately
    have write access to AD objects. Filtering these reduces noise
    in the RBCD write path output.
    """
    # Well-known SID suffixes for privileged groups
    privileged_rids = {
        "512",   # Domain Admins
        "519",   # Enterprise Admins
        "516",   # Domain Controllers
        "518",   # Schema Admins
        "520",   # Group Policy Creator Owners
    }
    # Well-known built-in SIDs
    privileged_sids = {
        "S-1-5-18",    # SYSTEM
        "S-1-5-32-544", # BUILTIN\Administrators
        "S-1-3-0",     # Creator Owner
    }

    if sid in privileged_sids:
        return True

    # Check RID suffix
    parts = sid.split("-")
    if parts and parts[-1] in privileged_rids:
        return True

    return False


# ---------------------------------------------------------------------------
# Main enumeration entry point
# ---------------------------------------------------------------------------

def run_enumeration(
    auth:   AuthContext,
    config: EnumConfig,
) -> EnumResult:
    """
    Main entry point for the enumeration module.
    Called by delegator.py when `enum` subcommand is used.

    Establishes the LDAP connection, runs the configured enumeration
    queries, correlates results into attack paths, and renders output.

    Returns an EnumResult for use by callers (e.g. exploitation modules
    that want to enumerate first then immediately exploit).
    """
    result = EnumResult()
    opsec  = OpsecCheck(enabled=config.opsec_check)

    # Build OpsecConfig for LDAP timing
    ldap_opsec = OpsecConfig(
        delay_ms=config.delay_ms,
        jitter_pct=config.jitter_pct,
        slow=config.slow,
    )

    # Establish LDAP connection
    info(f"Connecting to {config.dc_ip} ({config.domain})...")

    try:
        ldap_conn = connect(
            auth=auth,
            dc_ip=config.dc_ip,
            domain=config.domain,
            opsec=ldap_opsec,
        )
    except SystemExit:
        raise
    except Exception as e:
        error(f"Failed to connect to {config.dc_ip}: {e}")
        sys.exit(1)

    success(f"Connected as {auth.upn}")

    # Pull domain metadata
    domain_info = ldap_conn.get_domain_info()
    result.domain_info = domain_info

    if domain_info and not is_json_mode():
        dc_host = domain_info.get("dc_hostname", config.dc_ip)
        info(f"Domain controller: {dc_host}")

    # Determine which enumerations to run
    run_uncon = config.all_types or config.unconstrained
    run_const = config.all_types or config.constrained
    run_rbcd  = config.all_types or config.rbcd

    # Run enumeration queries
    if run_uncon:
        if opsec.check("ldap_enum_targeted"):
            result.unconstrained = enumerate_unconstrained(
                ldap_conn,
                opsec,
                check_reach=config.check_reachable,
            )

    if run_const:
        if opsec.check("ldap_enum_targeted"):
            result.constrained = enumerate_constrained(ldap_conn, opsec)

    if run_rbcd:
        if opsec.check("ldap_enum_full"):
            result.rbcd_paths = enumerate_rbcd_paths(ldap_conn, opsec, auth)

    # Correlate findings into attack paths
    if result.total_findings > 0:
        result.attack_paths = _correlate_attack_paths(
            unconstrained=result.unconstrained,
            constrained=result.constrained,
            rbcd_paths=result.rbcd_paths,
            current_user=auth.username,
            domain=config.domain,
        )

    # Render output
    if is_json_mode():
        json_data = build_json_output(
            unconstrained=result.unconstrained,
            constrained=result.constrained,
            rbcd_paths=result.rbcd_paths,
            attack_paths=result.attack_paths,
        )
        print_json(json_data)
    else:
        _render_results(result, config)

    ldap_conn.close()
    return result


def _render_results(result: EnumResult, config: EnumConfig) -> None:
    """Render the full enumeration output to the terminal."""

    # Tables
    if config.all_types or config.unconstrained:
        print_unconstrained_table(result.unconstrained)

    if config.all_types or config.constrained:
        print_constrained_table(result.constrained)

    if config.all_types or config.rbcd:
        print_rbcd_table(result.rbcd_paths)

    # Attack path correlation
    if result.attack_paths:
        print_attack_paths(result.attack_paths)

    # Summary
    divider()
    if result.total_findings == 0:
        info("No delegation misconfigurations found")
    else:
        success(
            f"Enumeration complete — "
            f"{result.total_findings} finding(s), "
            f"{len(result.attack_paths)} attack path(s) identified"
        )

        if result.critical_paths:
            from utils.output import critical
            critical(
                f"{len(result.critical_paths)} CRITICAL path(s) — "
                f"run exploit module to abuse"
            )

    # Noise summary
    if not is_json_mode():
        print()
        ops_run = []
        if config.all_types or config.unconstrained:
            ops_run.append("ldap_enum_targeted")
        if config.all_types or config.constrained:
            ops_run.append("ldap_enum_targeted")
        if config.all_types or config.rbcd:
            ops_run.append("ldap_enum_full")

        from utils.opsec import get_noise_summary
        noise = get_noise_summary(ops_run)
        info(
            f"OPSEC: max noise level this run — "
            f"{noise['max_noise']} "
            f"(events: {', '.join(noise['total_event_types'])})"
        )
    divider()
