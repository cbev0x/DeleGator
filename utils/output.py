"""
utils/output.py

Terminal output formatting for DeleGator.

Handles all visual output:
  - Banner with ASCII alligator
  - Status messages (info, success, warning, error)
  - Enumeration result tables
  - Attack path highlighting
  - Post-exploitation ticket output block
  - JSON output mode for tool chaining

Color scheme mirrors the banner design:
  Green  (#3fb950) — gator, success, findings
  Blue   (#58a6ff) — info, headers
  Amber  (#d29922) — tags, warnings, high value findings
  Grey   (#8b949e) — subtext, dimmed info
  Red    (#ff7b72) — errors, critical alerts
"""

import sys
import json
from typing import Optional, Any

# ---------------------------------------------------------------------------
# Colorama for cross-platform ANSI support
# ---------------------------------------------------------------------------

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

    # Fallback stubs so the rest of the module works without colorama
    class _Stub:
        def __getattr__(self, _):
            return ""

    class Fore(_Stub):   pass
    class Style(_Stub):  pass
    class Back(_Stub):   pass


# ---------------------------------------------------------------------------
# Color constants mapped to the DeleGator palette
# ---------------------------------------------------------------------------

class C:
    """Shorthand color constants."""
    GREEN   = Fore.GREEN        # success, findings
    BLUE    = Fore.CYAN         # info, headers (cyan reads better than blue in terminals)
    AMBER   = Fore.YELLOW       # warnings, high-value, tags
    GREY    = Fore.WHITE        # dimmed / subtext
    RED     = Fore.RED          # errors, critical
    BRIGHT  = Style.BRIGHT
    RESET   = Style.RESET_ALL
    DIM     = Style.DIM

    # Semantic aliases
    SUCCESS  = Fore.GREEN
    INFO     = Fore.CYAN
    WARN     = Fore.YELLOW
    ERROR    = Fore.RED
    CRITICAL = Fore.RED
    FINDING  = Fore.GREEN
    HIGH     = Fore.YELLOW
    LABEL    = Fore.CYAN


# ---------------------------------------------------------------------------
# Output mode — controls whether we print human-readable or JSON
# ---------------------------------------------------------------------------

_JSON_MODE  = False
_QUIET_MODE = False   # suppress banner and info messages, show findings only


def set_json_mode(enabled: bool) -> None:
    global _JSON_MODE
    _JSON_MODE = enabled


def set_quiet_mode(enabled: bool) -> None:
    global _QUIET_MODE
    _QUIET_MODE = enabled


def is_json_mode() -> bool:
    return _JSON_MODE


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
           .-._   _ _ _ _ _ _ _ _
.-''-.__.-' X  '-' ' ' ' ' ' ' ' '-.
'.___ '    .   .--_'-' '-' '-' _'-' '._
 V: V 'vv-'   '_   '.       .'  _..' '.'.
   '=.____.=_.--'   :_.__.__:_   '.   : :
           (((____.-'        '-.  /   : :
                             (((-'\ .' /
                           _____..'  .'
                          '-._____.-'
"""

TOOL_NAME = r"""
 ____  ___ _    ___   ___    ___   _____   ___   _____
|  _ \| __| |  | __| / __|  / _ \ |_   _| / _ \  |  _ )
| |_\ | _|| |_ | _| | (_ | / |_| \  | |  | |_| | | |\ \
|____/|___|___||___| \___| |_| |_|  |_|   \___/  |_| \_\
"""

TAGLINE    = "  Linux-native Kerberos delegation abuse  •  opsec-aware  •  enumeration-first"
TAGS       = "  [ unconstrained ]  [ constrained ]  [ rbcd ]  [ pass-the-ticket ]"
USAGE_LINE = "  usage: delegator.py enum | exploit  -d <domain> -u <user> [auth] [options]"
CREDIT     = "  by cbev  •  github.com/cbev0x/DeleGator"


def print_banner() -> None:
    """Print the full DeleGator banner."""
    if _JSON_MODE or _QUIET_MODE:
        return

    print(f"{C.GREEN}{C.BRIGHT}{BANNER}{C.RESET}", end="")
    print(f"{C.BLUE}{C.BRIGHT}{TOOL_NAME}{C.RESET}")
    print(f"{C.GREY}{TAGLINE}{C.RESET}")
    print(f"{C.AMBER}{TAGS}{C.RESET}")
    print()
    print(f"{C.GREY}{USAGE_LINE}{C.RESET}")
    print(f"{C.GREY}{CREDIT}{C.RESET}")
    print()
    print(f"  {C.GREY}{'─' * 68}{C.RESET}")
    print()


# ---------------------------------------------------------------------------
# Status message printers
# ---------------------------------------------------------------------------

def info(message: str) -> None:
    """General informational message."""
    if _JSON_MODE or _QUIET_MODE:
        return
    print(f"  {C.BLUE}[*]{C.RESET} {message}")


def success(message: str) -> None:
    """Success message — finding confirmed or operation succeeded."""
    if _JSON_MODE:
        return
    print(f"  {C.GREEN}{C.BRIGHT}[+]{C.RESET} {message}")


def warning(message: str) -> None:
    """Warning — something notable but not fatal."""
    if _JSON_MODE:
        return
    print(f"  {C.AMBER}[!]{C.RESET} {message}")


def error(message: str) -> None:
    """Error message — always printed regardless of mode."""
    print(f"\n  {C.RED}[!]{C.RESET} {C.RED}{message}{C.RESET}\n", file=sys.stderr)


def critical(message: str) -> None:
    """Critical finding — high-value attack path identified."""
    if _JSON_MODE:
        return
    print(f"  {C.RED}{C.BRIGHT}[!!]{C.RESET} {C.AMBER}{C.BRIGHT}{message}{C.RESET}")


def section(title: str) -> None:
    """Print a section header to visually separate output blocks."""
    if _JSON_MODE or _QUIET_MODE:
        return
    print()
    print(f"  {C.BLUE}{C.BRIGHT}{title.upper()}{C.RESET}")
    print(f"  {C.GREY}{'─' * len(title)}{C.RESET}")


def divider() -> None:
    """Print a thin horizontal divider."""
    if _JSON_MODE or _QUIET_MODE:
        return
    print(f"  {C.GREY}{'─' * 68}{C.RESET}")


# ---------------------------------------------------------------------------
# Enumeration result tables
# ---------------------------------------------------------------------------

def _truncate(value: Any, max_len: int) -> str:
    """Truncate a string to max_len with ellipsis."""
    s = str(value) if value is not None else ""
    return s if len(s) <= max_len else s[:max_len - 3] + "..."


def _col(value: Any, width: int, color: str = "") -> str:
    """Format a single table column with fixed width and optional color."""
    cell = _truncate(str(value) if value else "", width)
    padded = cell.ljust(width)
    if color:
        return f"{color}{padded}{C.RESET}"
    return padded


def print_unconstrained_table(results: list[dict]) -> None:
    """
    Print unconstrained delegation findings as a formatted table.

    Columns: Account | Type | Reachable | Coercible | Last Logon
    """
    if not results:
        info("No unconstrained delegation configured (excluding DCs)")
        return

    section("Unconstrained Delegation")

    header = (
        f"  {'Account':<25} {'Type':<10} {'Reachable':<12} "
        f"{'Coercible':<20} {'Last Logon':<20}"
    )
    print(f"{C.BLUE}{header}{C.RESET}")
    print(f"  {C.GREY}{'─' * 87}{C.RESET}")

    for entry in results:
        account    = entry.get("sAMAccountName", "?")
        obj_class  = entry.get("objectClass", [])
        obj_type   = "Computer" if "computer" in str(obj_class).lower() else "User"
        reachable  = entry.get("_reachable", "Unknown")
        coercible  = entry.get("_coercible", [])
        last_logon = entry.get("_last_logon", "Unknown")

        coerce_str = ", ".join(coercible) if coercible else "Unknown"

        reachable_color = C.GREEN if reachable is True else (
            C.RED if reachable is False else C.GREY
        )

        print(
            f"  {C.AMBER}{account:<25}{C.RESET}"
            f" {C.GREY}{obj_type:<10}{C.RESET}"
            f" {reachable_color}{str(reachable):<12}{C.RESET}"
            f" {C.GREY}{coerce_str:<20}{C.RESET}"
            f" {C.GREY}{str(last_logon):<20}{C.RESET}"
        )


def print_constrained_table(results: list[dict]) -> None:
    """
    Print constrained delegation findings as a formatted table.

    Columns: Account | Protocol Transition | Delegatable SPNs | High Value
    """
    if not results:
        info("No constrained delegation configured")
        return

    section("Constrained Delegation")

    header = (
        f"  {'Account':<25} {'Proto Transition':<18} "
        f"{'Delegatable SPNs':<40} {'Flag':<10}"
    )
    print(f"{C.BLUE}{header}{C.RESET}")
    print(f"  {C.GREY}{'─' * 93}{C.RESET}")

    for entry in results:
        account    = entry.get("sAMAccountName", "?")
        uac        = entry.get("userAccountControl") or 0
        # TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000 = 16777216
        proto_trans = bool(int(uac) & 16777216) if uac else False
        spns       = entry.get("msDS-AllowedToDelegateTo") or []
        if isinstance(spns, str):
            spns = [spns]
        high_value = entry.get("_high_value", False)

        spn_str    = ", ".join(spns) if spns else "None"
        pt_str     = "YES" if proto_trans else "NO"
        pt_color   = C.GREEN if proto_trans else C.GREY
        flag_str   = f"{C.RED}⚠ HIGH VALUE{C.RESET}" if high_value else ""

        print(
            f"  {C.AMBER}{account:<25}{C.RESET}"
            f" {pt_color}{pt_str:<18}{C.RESET}"
            f" {C.GREY}{_truncate(spn_str, 40):<40}{C.RESET}"
            f" {flag_str}"
        )


def print_rbcd_table(results: list[dict]) -> None:
    """
    Print RBCD write-permission findings as a formatted table.

    Columns: Target Computer | Writable By | Current User Has Write | Risk
    """
    if not results:
        info("No RBCD write paths identified for current user")
        return

    section("RBCD Write Paths")

    header = (
        f"  {'Target Computer':<25} {'Writable By':<25} "
        f"{'You Can Write':<15} {'Risk':<10}"
    )
    print(f"{C.BLUE}{header}{C.RESET}")
    print(f"  {C.GREY}{'─' * 75}{C.RESET}")

    for entry in results:
        target      = entry.get("sAMAccountName", "?")
        writable_by = entry.get("_writable_by", "?")
        you_write   = entry.get("_current_user_writable", False)
        risk        = entry.get("_risk", "MEDIUM")

        write_color = C.GREEN if you_write else C.GREY
        risk_color  = C.RED if risk == "CRITICAL" else (
            C.AMBER if risk == "HIGH" else C.GREY
        )

        print(
            f"  {C.AMBER}{target:<25}{C.RESET}"
            f" {C.GREY}{writable_by:<25}{C.RESET}"
            f" {write_color}{str(you_write):<15}{C.RESET}"
            f" {risk_color}{risk:<10}{C.RESET}"
        )


def print_attack_paths(paths: list[dict]) -> None:
    """
    Print identified attack paths — the high-value correlation output
    that chains individual findings into actionable exploitation routes.

    This is one of the most important outputs in the tool and gets
    prominent visual treatment.
    """
    if not paths:
        return

    section("Attack Paths Identified")

    for path in paths:
        severity    = path.get("severity", "MEDIUM").upper()
        description = path.get("description", "")
        steps       = path.get("steps", [])

        sev_color = (
            C.RED    if severity == "CRITICAL" else
            C.AMBER  if severity == "HIGH"     else
            C.GREY
        )

        print(
            f"  {sev_color}{C.BRIGHT}[{severity}]{C.RESET} "
            f"{C.BRIGHT}{description}{C.RESET}"
        )

        if steps:
            for i, step in enumerate(steps, 1):
                connector = "└─" if i == len(steps) else "├─"
                print(f"  {C.GREY}    {connector} {step}{C.RESET}")

        print()


# ---------------------------------------------------------------------------
# Post-exploitation ticket output
# ---------------------------------------------------------------------------

def print_ticket_result(
    ccache_path:       str,
    impersonated_user: str,
    target_spn:        str,
    netexec_cmd:       str,
    impacket_cmd:      str,
    delegation_type:   str,
) -> None:
    """
    Print the post-exploitation output block shown after a successful
    delegation abuse. Designed to be immediately actionable — the operator
    can copy/paste the commands without any additional processing.
    """
    if _JSON_MODE:
        return

    print()
    divider()
    print(f"  {C.GREEN}{C.BRIGHT}[+] Ticket obtained successfully{C.RESET}")
    divider()
    print()

    print(f"  {C.LABEL}Delegation Type  {C.RESET}: {C.AMBER}{delegation_type}{C.RESET}")
    print(f"  {C.LABEL}Impersonating    {C.RESET}: {C.GREEN}{C.BRIGHT}{impersonated_user}{C.RESET}")
    print(f"  {C.LABEL}Target SPN       {C.RESET}: {C.GREY}{target_spn}{C.RESET}")
    print(f"  {C.LABEL}ccache written   {C.RESET}: {C.GREEN}{ccache_path}{C.RESET}")
    print()

    print(f"  {C.BLUE}# Export the ticket{C.RESET}")
    print(f"  {C.BRIGHT}export KRB5CCNAME={ccache_path}{C.RESET}")
    print()

    print(f"  {C.BLUE}# Use with NetExec{C.RESET}")
    print(f"  {C.BRIGHT}{netexec_cmd}{C.RESET}")
    print()

    print(f"  {C.BLUE}# Use with Impacket{C.RESET}")
    print(f"  {C.BRIGHT}{impacket_cmd}{C.RESET}")
    print()
    divider()
    print()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def print_json(data: dict) -> None:
    """
    Print structured JSON output for tool chaining.
    Only active when --json flag is passed.
    """
    print(json.dumps(data, indent=2, default=str))


def build_json_output(
    unconstrained: list[dict],
    constrained:   list[dict],
    rbcd_paths:    list[dict],
    attack_paths:  list[dict],
) -> dict:
    """
    Build the structured JSON output dict for --json mode.
    This is what gets piped into other tools or saved for reporting.
    """
    return {
        "delegator": {
            "version": "0.1.0",
            "findings": {
                "unconstrained":  unconstrained,
                "constrained":    constrained,
                "rbcd_writable":  rbcd_paths,
                "attack_paths":   attack_paths,
            },
            "summary": {
                "unconstrained_count": len(unconstrained),
                "constrained_count":   len(constrained),
                "rbcd_paths_count":    len(rbcd_paths),
                "attack_paths_count":  len(attack_paths),
                "critical_paths":      sum(
                    1 for p in attack_paths
                    if p.get("severity", "").upper() == "CRITICAL"
                ),
            }
        }
    }


# ---------------------------------------------------------------------------
# Opsec warning helper
# ---------------------------------------------------------------------------

def opsec_warning(action: str, events: list[str]) -> bool:
    """
    Warn the operator before an action that generates detectable events
    and prompt for confirmation. Returns True if they confirm, False to abort.

    Only shown when --opsec-check flag is active.
    """
    if _JSON_MODE:
        return True

    print()
    print(f"  {C.AMBER}{C.BRIGHT}[OPSEC WARNING]{C.RESET}")
    print(f"  {C.GREY}Action  : {C.RESET}{action}")
    print(f"  {C.GREY}Generates:{C.RESET}")
    for event in events:
        print(f"    {C.AMBER}• {event}{C.RESET}")
    print()

    try:
        response = input(f"  {C.AMBER}Proceed? [y/N]{C.RESET} ").strip().lower()
        return response == "y"
    except (KeyboardInterrupt, EOFError):
        print()
        return False
