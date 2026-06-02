"""
core/auth.py

Unified authentication handler for DeleGator.
Supports four authentication methods:
  - Password (plaintext)
  - NTLM hash (pass-the-hash)
  - Kerberos ccache (pass-the-ticket)
  - Certificate (PFX or cert+key pair)

All methods return an AuthContext object that downstream modules
consume without needing to know which auth method was used.
"""

import os
import sys
import ssl
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from impacket.krb5.ccache import CCache
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal
from impacket.ntlm import compute_lmhash, compute_nthash
from OpenSSL import crypto


# ---------------------------------------------------------------------------
# Auth method enum
# ---------------------------------------------------------------------------

class AuthMethod(Enum):
    PASSWORD  = auto()
    HASH      = auto()
    CCACHE    = auto()
    CERT      = auto()


# ---------------------------------------------------------------------------
# AuthContext — the unified object passed to all downstream modules
# ---------------------------------------------------------------------------

@dataclass
class AuthContext:
    """
    Carries everything a downstream module needs to authenticate
    against LDAP or request Kerberos tickets.

    Fields are populated based on the auth method used; unused fields
    are None so modules can inspect auth_method when behaviour differs.
    """
    username:   str
    domain:     str
    auth_method: AuthMethod

    # Password auth
    password:   Optional[str]   = None

    # Hash auth — stored as the full LM:NT string and split components
    lm_hash:    Optional[str]   = None
    nt_hash:    Optional[str]   = None

    # Ccache auth
    ccache_path: Optional[str]  = None
    tgt:         Optional[dict] = None     # decoded TGT for Impacket consumers

    # Certificate auth
    cert_pem:    Optional[bytes] = None   # PEM-encoded certificate
    key_pem:     Optional[bytes] = None   # PEM-encoded private key

    # Derived — FQDN of the domain (lowercased) used in LDAP URIs
    domain_fqdn: str = field(init=False)

    def __post_init__(self):
        self.domain_fqdn = self.domain.lower()

    @property
    def upn(self) -> str:
        """Return user@domain UPN format."""
        return f"{self.username}@{self.domain_fqdn}"

    @property
    def nt_only(self) -> str:
        """Return just the NT hash portion, used in most Impacket calls."""
        return self.nt_hash or ""

    def __repr__(self) -> str:
        method_str = self.auth_method.name.lower()
        return (
            f"AuthContext(user={self.upn}, "
            f"method={method_str})"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _die(message: str) -> None:
    """Print a formatted error and exit immediately."""
    print(f"\n  [!] Auth error: {message}\n", file=sys.stderr)
    sys.exit(1)


def _normalise_hash(raw: str) -> tuple[str, str]:
    """
    Accept NT hash in any of these formats and return (lm, nt):
      - aad3b435...:fc525c96...   (LM:NT)
      - fc525c96...               (NT only — LM is zeroed)
      - :fc525c96...              (colon-prefixed NT only)
    """
    raw = raw.strip()

    if ":" in raw:
        parts = raw.split(":", 1)
        lm = parts[0] if parts[0] else "aad3b435b51404eeaad3b435b51404ee"
        nt = parts[1]
    else:
        # Bare 32-char hex string — treat as NT only
        lm = "aad3b435b51404eeaad3b435b51404ee"
        nt = raw

    # Basic sanity check
    for label, value in [("LM hash", lm), ("NT hash", nt)]:
        if len(value) != 32:
            _die(f"Invalid {label} length ({len(value)} chars, expected 32): {value}")
        try:
            int(value, 16)
        except ValueError:
            _die(f"{label} contains non-hex characters: {value}")

    return lm, nt


def _load_pfx(pfx_path: str, pfx_pass: Optional[str]) -> tuple[bytes, bytes]:
    """
    Load a PFX/PKCS12 file and return (cert_pem, key_pem).
    Exits cleanly if the file cannot be read or decrypted.
    """
    if not os.path.isfile(pfx_path):
        _die(f"PFX file not found: {pfx_path}")

    try:
        with open(pfx_path, "rb") as f:
            pfx_data = f.read()
    except PermissionError:
        _die(f"Cannot read PFX file (permission denied): {pfx_path}")

    passphrase = pfx_pass.encode() if pfx_pass else None

    try:
        p12 = crypto.load_pkcs12(pfx_data, passphrase)
    except crypto.Error:
        _die(
            "Failed to decrypt PFX file. "
            "Check the password is correct (use --pfx-pass if required)."
        )

    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())
    key_pem  = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())

    return cert_pem, key_pem


def _load_cert_key(cert_path: str, key_path: str) -> tuple[bytes, bytes]:
    """
    Load a PEM certificate and PEM private key from separate files.
    Exits cleanly if either file cannot be read.
    """
    for label, path in [("Certificate", cert_path), ("Key", key_path)]:
        if not os.path.isfile(path):
            _die(f"{label} file not found: {path}")
        if not os.access(path, os.R_OK):
            _die(f"Cannot read {label.lower()} file (permission denied): {path}")

    with open(cert_path, "rb") as f:
        cert_pem = f.read()
    with open(key_path, "rb") as f:
        key_pem = f.read()

    # Validate both are readable PEM structures
    try:
        crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    except crypto.Error as e:
        _die(f"Certificate file does not appear to be valid PEM: {e}")

    try:
        crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem)
    except crypto.Error as e:
        _die(f"Key file does not appear to be valid PEM: {e}")

    return cert_pem, key_pem


def _resolve_ccache(ccache_path: Optional[str]) -> str:
    """
    Resolve the ccache path to use.
    Priority: explicit path > KRB5CCNAME env var > error.
    """
    if ccache_path:
        if not os.path.isfile(ccache_path):
            _die(f"ccache file not found: {ccache_path}")
        return ccache_path

    env_path = os.environ.get("KRB5CCNAME")
    if env_path:
        # KRB5CCNAME may be prefixed with "FILE:" in some tools
        env_path = env_path.replace("FILE:", "").strip()
        if not os.path.isfile(env_path):
            _die(
                f"KRB5CCNAME is set to '{env_path}' but the file does not exist. "
                "Re-export a valid ccache or provide --ccache explicitly."
            )
        return env_path

    _die(
        "Kerberos auth requested but no ccache provided. "
        "Either pass --ccache /path/to/file.ccache or "
        "set the KRB5CCNAME environment variable."
    )


def _parse_ccache(ccache_path: str, username: str, domain: str) -> dict:
    """
    Load and validate a ccache file using Impacket's CCache parser.
    Returns the first credential found — works with both TGTs and service tickets.
    Exits if the ccache cannot be parsed or contains no credentials.
    """
    try:
        ccache = CCache.loadFile(ccache_path)
    except Exception as e:
        _die(f"Failed to parse ccache file '{ccache_path}': {e}")

    if not ccache.credentials:
        _die(
            f"ccache file '{ccache_path}' contains no credentials. "
            "The ticket may have expired or the file may be empty."
        )

    # Return first credential — works for TGTs and service tickets alike
    return ccache.credentials[0]


# ---------------------------------------------------------------------------
# Public factory functions — one per auth method
# ---------------------------------------------------------------------------

def auth_password(username: str, domain: str, password: str) -> AuthContext:
    """
    Authenticate using a plaintext password.
    Minimal validation — real auth failure will surface at LDAP bind time.
    """
    if not password:
        _die("Password cannot be empty. Use -p or --password.")

    return AuthContext(
        username=username,
        domain=domain,
        auth_method=AuthMethod.PASSWORD,
        password=password,
    )


def auth_hash(username: str, domain: str, hash_str: str) -> AuthContext:
    """
    Authenticate using an NTLM hash (pass-the-hash).
    Accepts LM:NT, :NT, or bare NT formats.
    """
    lm, nt = _normalise_hash(hash_str)

    return AuthContext(
        username=username,
        domain=domain,
        auth_method=AuthMethod.HASH,
        lm_hash=lm,
        nt_hash=nt,
    )


def auth_ccache(
    username: str,
    domain: str,
    ccache_path: Optional[str] = None,
) -> AuthContext:
    """
    Authenticate using a Kerberos ccache ticket.
    If ccache_path is None, falls back to KRB5CCNAME environment variable.
    """
    resolved_path = _resolve_ccache(ccache_path)
    tgt = _parse_ccache(resolved_path, username, domain)

    return AuthContext(
        username=username,
        domain=domain,
        auth_method=AuthMethod.CCACHE,
        ccache_path=resolved_path,
        tgt=tgt,
    )


def auth_pfx(
    username: str,
    domain: str,
    pfx_path: str,
    pfx_pass: Optional[str] = None,
) -> AuthContext:
    """
    Authenticate using a PFX/PKCS12 certificate file.
    Used for certificate-based Kerberos authentication (PKINIT).
    """
    cert_pem, key_pem = _load_pfx(pfx_path, pfx_pass)

    return AuthContext(
        username=username,
        domain=domain,
        auth_method=AuthMethod.CERT,
        cert_pem=cert_pem,
        key_pem=key_pem,
    )


def auth_cert(
    username: str,
    domain: str,
    cert_path: str,
    key_path: str,
) -> AuthContext:
    """
    Authenticate using separate PEM certificate and key files.
    Alternative to PFX for environments where cert and key are stored separately.
    """
    cert_pem, key_pem = _load_cert_key(cert_path, key_path)

    return AuthContext(
        username=username,
        domain=domain,
        auth_method=AuthMethod.CERT,
        cert_pem=cert_pem,
        key_pem=key_pem,
    )


# ---------------------------------------------------------------------------
# Unified entry point — called by the argument parser
# ---------------------------------------------------------------------------

def build_auth_context(args) -> AuthContext:
    """
    Dispatch to the appropriate auth factory based on parsed CLI arguments.

    Expected args attributes (all optional except username and domain):
      args.username   str
      args.domain     str
      args.password   str | None
      args.hashes     str | None     LM:NT or :NT or NT
      args.ccache     str | None     explicit ccache path
      args.pfx        str | None     path to PFX file
      args.pfx_pass   str | None     PFX decryption password
      args.cert       str | None     path to PEM certificate
      args.key        str | None     path to PEM private key

    Exactly one auth method must be specified. Exits with an error if
    zero or multiple methods are detected.
    """
    username = args.username
    domain   = args.domain

    if not username:
        _die("Username is required (-u / --username).")
    if not domain:
        _die("Domain is required (-d / --domain).")

    # Determine which auth methods were supplied
    has_password = bool(getattr(args, "password", None))
    has_hash     = bool(getattr(args, "hashes",   None))
    has_ccache   = bool(getattr(args, "ccache",   None)) or bool(os.environ.get("KRB5CCNAME"))
    has_cert     = bool(getattr(args, "pfx",      None)) or (
                       bool(getattr(args, "cert", None)) and
                       bool(getattr(args, "key",  None))
                   )

    methods_supplied = sum([has_password, has_hash, has_ccache, has_cert])

    if methods_supplied == 0:
        _die(
            "No authentication method provided. Supply one of:\n"
            "  -p PASSWORD\n"
            "  -H HASH (LM:NT or :NT)\n"
            "  --ccache /path/to/file.ccache  (or set KRB5CCNAME)\n"
            "  --pfx /path/to/file.pfx\n"
            "  --cert /path/to/cert.pem --key /path/to/key.pem"
        )

    if methods_supplied > 1:
        _die(
            "Multiple authentication methods detected. "
            "Provide exactly one of: -p, -H, --ccache, --pfx, --cert+--key."
        )

    # Dispatch
    if has_password:
        return auth_password(username, domain, args.password)

    if has_hash:
        return auth_hash(username, domain, args.hashes)

    if has_ccache:
        return auth_ccache(username, domain, getattr(args, "ccache", None))

    if has_cert:
        if getattr(args, "pfx", None):
            return auth_pfx(username, domain, args.pfx, getattr(args, "pfx_pass", None))
        return auth_cert(username, domain, args.cert, args.key)
