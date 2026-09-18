"""Command line interface for cfscan.

``cfscan`` with no arguments opens the interactive menu. The flags below make
the same operations available to scripts and to users who prefer shortcuts.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__, source_note
from .menu import (
    EXIT_FAILED,
    EXIT_INTERRUPTED,
    EXIT_MISSING_TOOL,
    EXIT_OK,
    EXIT_USAGE,
    Session,
    make_pool_flow,
    multi_isp_report,
    multi_isp_round,
    quick_scan,
    run_menu,
    edge_locations,
    show_last_results,
    show_profiles,
    update_ranges_flow,
    verify_flow,
)
from .profiles import Paths, UnknownProfile, load_config
from .runner import CfstNotFoundError, ScanError
from .ui import Aborted, Console, supports_ansi
from .validate import ValidationError, validate_colo

__all__ = ["build_parser", "main", "source_note"]

HELP_TEXT = """
cfscan - a friendly wrapper around XIU2/CloudflareSpeedTest (the cfst binary).

Usage:
  cfscan                              open the interactive menu
  cfscan --quick [--yes]              scan with the active profile
  cfscan --profile NAME               use another saved profile
  cfscan --verify IP                  verify one address (20 attempts, 0% loss)
  cfscan --show-last                  show the newest saved result
  cfscan --list-profiles              list saved profiles
  cfscan --quick --dry-run            print the cfst argument list, run nothing
  cfscan --make-pool 2000             fix the candidate list for every round
  cfscan --isp NAME [--pool FILE]     measure one carrier against that list
  cfscan --multi-isp                  print the report of the stored session
  cfscan --colo FRA,AMS               keep only those datacentres in this scan
  cfscan --colo any                   measure every datacentre, ignoring the
                                      filter saved in the profile
  cfscan --update-ranges              download Cloudflare's current range lists
  cfscan --edges                      rank datacentres from what you measured
  cfscan --no-verify-top              skip the strict check of the best addresses
  cfscan --no-preflight               skip the one-address check made before a scan
  cfscan --direct                     scan without this shell's proxy variables
  cfscan --no-color                   disable ANSI colours
  cfscan --version                    print the version
  cfscan --help                       print this help

Multi-carrier scans:
  The scanner draws a fresh sample of the range file on every run (measured:
  5,955 of 1,524,480 addresses, and two runs shared no address at all), so two
  runs can never be compared address by address. A carrier comparison therefore
  fixes the candidate list once - 'cfscan --make-pool 2000' writes it - and every
  round measures that same list. Menu 10 does all of it in one sitting: it asks
  how many carriers first, then one round each, waiting between rounds so the
  connection can be switched. Each round is stored as it finishes under the
  results folder (multi-isp/<domain>/<session>.json), so a dropped hotspot costs
  one round and not the session. The report lists the addresses that passed on
  every carrier (ranked by worst-case latency, so an address that is fast on one
  carrier and slow on another does not win), the fastest verified address per
  carrier, and - when nothing passed everywhere - the address covering the most
  carriers. 'cfscan --multi-isp' prints that report again from the stored file,
  and 'cfscan --isp NAME' adds a single round to the newest session.

Region filter:
  Cloudflare answers from the datacentre nearest to your line, and which one
  that is decides the latency far more than the address does. '--colo FRA,AMS'
  (or a filter saved in the profile) keeps only the addresses whose datacentre
  you named, using the CF-RAY header the edge returns. Measured on one line:
  an unfiltered scan returned 1,385 addresses in GYD and two in FRA, while
  'FRA,AMS,LHR' returned 36 addresses, all of them in FRA or LHR at 138-150 ms.
  It needs HTTPing with scheme=https: TCPing never reads a header, and plain
  HTTP to an HTTPS port makes the edge answer its own 400, whose CF-RAY is
  empty - so in both cases the filter would drop every address. cfscan says so
  instead of letting that happen.
  The filter is never a one-way door: menu 2 and menu 12 both offer "measure
  every datacentre" as a choice on screen, menu 6 edits it without running a
  scan, and 'cfscan --colo any' ignores the saved filter for one run.
  Which datacentres to name is not a question of distance - the nearest one
  measured worst of all on the line above - so cfscan does not guess it from a
  map. Every scan records which datacentres answered and how fast, and
  'cfscan --edges' (menu 12) ranks them from that and suggests the filter. The
  ranking is kept per line, because a scan taken through a tunnel describes the
  tunnel's path and not this machine's own: mixing the two would describe
  neither. cfscan says which line it is ranking, and warns when the default
  route is a tunnel.

Notes:
  The scanner honours the proxy variables of this shell (HTTPS_PROXY and friends),
  so a VPN proxy exported in the terminal carries every test request. cfscan says
  which variables were inherited before the first scan. Use --direct (or unset
  them) when the numbers should describe this machine's own connection instead.
  Before a scan, one Cloudflare address is measured with the profile's own test
  URL. When that fails, cfscan says why - a scheme the port does not speak, a
  hostname Cloudflare does not serve, an origin that is down - instead of
  spending minutes over the whole range and reporting "no result". Use
  --no-preflight to skip it.
  After a scan the ten best addresses are re-measured in one extra scanner run
  (20 attempts each, 0% packet loss required) and marked PASS, FAIL or DEAD, so
  the list you copy from is a measurement, not a guess. Use --no-verify-top (or
  "verify_top_ips": false in a profile) to skip that step.
  Tests started from the menu print their result and then return to the menu
  (press Enter when asked). Ctrl+C cancels the current step; option 0 exits.
  A one-shot command such as 'cfscan --quick --yes' prints its result and exits,
  which is what scripts want.

Safety:
  The scanner is always started with an argument list, never through a shell,
  so no value you type can become a command. cfscan never changes your DNS or
  VPN settings, and it never asks for a UUID, password, private key or
  subscription link.

Files:
  Configuration: ~/.config/cfscan/config.json
  Results:       ~/Documents/Cloudflare Scanner Results/
"""


#: The largest candidate list ``--make-pool`` accepts: a typo should not ask for
#: a list that would take hours to scan on every carrier.
MAX_POOL_SIZE = 200000

#: Flags that each start a command of their own. Combining two of them would
#: make the outcome depend on the order of this file, so it is refused instead.
COMMAND_FLAGS = (
    ("--list-profiles", "list the saved profiles"),
    ("--show-last", "show the newest saved result"),
    ("--verify", "verify one address"),
    ("--quick", "run a scan"),
    ("--make-pool", "write a candidate list"),
    ("--multi-isp", "print the multi-carrier report"),
    ("--isp", "measure one carrier"),
    ("--update-ranges", "download the current range lists"),
    ("--edges", "rank the datacentres measured so far"),
)


class UsageError(Exception):
    """Raised instead of argparse's own exit-on-error behaviour."""


def pool_size_value(value):
    """argparse type for ``--make-pool``: a whole number, 0 meaning "default"."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"'{value}' is not a whole number")
    if number < 0:
        raise argparse.ArgumentTypeError(
            "the candidate list size cannot be negative (use 0 or leave the "
            "number out for the default)"
        )
    if number > MAX_POOL_SIZE:
        raise argparse.ArgumentTypeError(
            f"{number} addresses is more than a carrier comparison needs "
            f"(the maximum is {MAX_POOL_SIZE})"
        )
    return number


class _Parser(argparse.ArgumentParser):
    """An ArgumentParser that never writes to the real stdout or exits."""

    def error(self, message):
        raise UsageError(message)

    def exit(self, status=0, message=None):  # pragma: no cover - safety net
        raise UsageError(message or "unexpected usage error")

    def print_help(self, file=None):  # pragma: no cover - safety net
        raise UsageError("help")


def build_parser():
    parser = _Parser(
        prog="cfscan",
        add_help=False,
        description="Friendly wrapper around the CloudflareSpeedTest scanner.",
        epilog=HELP_TEXT,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-h", "--help", action="store_true",
                        help="show the full help and exit")
    parser.add_argument("--version", action="store_true",
                        help="print the version and exit")
    parser.add_argument("--quick", action="store_true",
                        help="run a scan with the active profile and exit")
    parser.add_argument("--verify", metavar="IP", default=None,
                        help="verify one IP address with 20 attempts")
    parser.add_argument("--profile", metavar="NAME", default=None,
                        help="use a specific saved profile")
    parser.add_argument("--list-profiles", action="store_true",
                        help="list the saved profiles and exit")
    parser.add_argument("--show-last", action="store_true",
                        help="show the newest saved result and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the cfst argument list without running it")
    parser.add_argument("--yes", action="store_true",
                        help="skip the confirmation prompt for scans")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colours")
    parser.add_argument("--no-verify-top", action="store_true",
                        help="do not verify the best addresses after a scan")
    parser.add_argument("--no-preflight", action="store_true",
                        help="skip the one-address check made before a scan")
    parser.add_argument("--direct", action="store_true",
                        help="run the scanner without this shell's proxy variables")
    parser.add_argument("--make-pool", metavar="SIZE", nargs="?", const=0,
                        type=pool_size_value, default=None,
                        help="write the candidate list every carrier round shares")
    parser.add_argument("--isp", metavar="NAME", default=None,
                        help="measure one carrier and add it to the session")
    parser.add_argument("--pool", metavar="FILE", default=None,
                        help="use this candidate list instead of building one")
    parser.add_argument("--multi-isp", action="store_true",
                        help="print the multi-carrier report of the session")
    parser.add_argument("--session", metavar="FILE", default=None,
                        help="read this multi-carrier session for --multi-isp")
    parser.add_argument("--note", metavar="TEXT", default=None,
                        help="a label stored with a carrier round (access type)")
    parser.add_argument("--colo", metavar="CODES", default=None,
                        help="keep only these Cloudflare datacentres (FRA,AMS); "
                             "'any' measures all of them for this run")
    parser.add_argument("--update-ranges", action="store_true",
                        help="download Cloudflare's current IP range lists")
    parser.add_argument("--edges", action="store_true",
                        help="rank the datacentres measured so far")
    return parser


def _print_help(console):
    for line in HELP_TEXT.strip("\n").splitlines():
        console.line(line)


def _make_console(no_color=False):
    return Console(color=supports_ansi(no_color=no_color))


def main(argv=None, paths=None, console=None, spawn=None):
    """Entry point. Returns the process exit code."""
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    parser = build_parser()

    try:
        args = parser.parse_args(argv)
    except UsageError as exc:
        cons = console if console is not None else _make_console()
        cons.error(f"Invalid usage: {exc}")
        _print_help(cons)
        return EXIT_USAGE

    if console is None:
        console = _make_console(no_color=args.no_color)
    elif args.no_color:
        console.set_color(False)

    if args.help:
        _print_help(console)
        return EXIT_OK

    if args.version:
        console.line(f"cfscan {__version__}")
        console.line(source_note())
        return EXIT_OK

    # Any None default would hide a flag that is present but carries no value
    # ("--make-pool" on its own uses the default size), so the flags themselves
    # are looked up in what the user typed.
    chosen = [
        (flag, description) for flag, description in COMMAND_FLAGS
        if any(item == flag or item.startswith(flag + "=") for item in argv)
    ]
    if len(chosen) > 1:
        console.error("Give one command at a time: "
                      + ", ".join(f"{flag} ({text})" for flag, text in chosen))
        return EXIT_USAGE

    if (args.pool or args.note) and args.isp is None:
        console.error("--pool and --note describe one carrier round, so they need "
                      "--isp NAME.")
        return EXIT_USAGE

    if args.session and not args.multi_isp:
        console.error("--session names the file that --multi-isp should read.")
        return EXIT_USAGE

    paths = paths if paths is not None else Paths()
    try:
        config = load_config(paths)
    except OSError as exc:
        console.error(f"The configuration could not be read or created: {exc}")
        return EXIT_FAILED

    session = Session(
        paths=paths,
        console=console,
        spawn=spawn,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        verify_top_ips=not args.no_verify_top,
        preflight=not args.no_preflight,
        direct=args.direct,
    )

    # Validated once, here, rather than inside the flows that happen to use it:
    # "--profile nosuch --list-profiles" used to list the profiles and say
    # nothing, so a typo looked like it had worked.
    if args.profile is not None and args.profile not in (config.get("profiles") or {}):
        available = ", ".join(config.get("profiles") or {}) or "none"
        console.error(f"Unknown profile '{args.profile}'. "
                      f"Available profiles: {available}.")
        return EXIT_USAGE

    if args.colo is not None:
        # A one-run override: the profile on disk is not touched, so trying a
        # region never quietly rewrites a saved profile.
        try:
            wanted = validate_colo(args.colo)
        except ValidationError as exc:
            console.error(str(exc))
            return EXIT_USAGE
        target = args.profile or config.get("active_profile")
        if target not in (config.get("profiles") or {}):
            console.error(f"--colo needs a profile that exists; '{target}' does "
                          "not.")
            return EXIT_USAGE
        # Held on the session, not written into the profile: the flows save the
        # profile for their own reasons, and a one-run experiment must not ride
        # along into the stored configuration.
        session.colo_override = wanted
        console.info(f"Region filter for this run: {wanted or 'any datacentre'}"
                     " (the saved profile is unchanged).")

    try:
        if args.update_ranges:
            # Typed by the user, so it may run unattended in a script.
            return update_ranges_flow(session, config,
                                      profile_name=args.profile,
                                      allow_unattended=True)
        if args.edges:
            return edge_locations(session, config, profile_name=args.profile)
        if args.list_profiles:
            return show_profiles(session, config)
        if args.make_pool is not None:
            return make_pool_flow(session, config, size=args.make_pool or None,
                                  profile_name=args.profile)
        if args.multi_isp:
            return multi_isp_report(session, config, profile_name=args.profile,
                                    session_path=args.session)
        if args.isp is not None:
            return multi_isp_round(session, config, profile_name=args.profile,
                                   isp=args.isp, pool_path=args.pool,
                                   note=args.note)
        if args.show_last:
            return show_last_results(session, config)
        if args.verify is not None:
            return verify_flow(session, config, ip=args.verify,
                               profile_name=args.profile)
        if args.quick:
            return quick_scan(session, config, profile_name=args.profile,
                              verify_prompt=False)
        if args.profile is not None:
            # Validate the name up front, then use it for this interactive
            # session so the menu works on the profile the user asked for.
            if args.profile not in (config.get("profiles") or {}):
                available = ", ".join(config.get("profiles") or {}) or "none"
                raise UnknownProfile(f"Unknown profile '{args.profile}'. "
                                     f"Available profiles: {available}.")
            config["active_profile"] = args.profile
            console.info(f"Using profile '{args.profile}' for this session.")
        return run_menu(session, config)
    except UnknownProfile as exc:
        console.error(str(exc))
        available = ", ".join(config.get("profiles") or {}) or "none"
        console.line(f"Available profiles: {available}")
        return EXIT_USAGE
    except ValidationError as exc:
        # A value the flow could not use (a candidate list that is missing, an
        # IPv6 profile asked for an IPv4 pool): say it, do not traceback.
        console.error(str(exc))
        return EXIT_USAGE
    except Aborted:
        console.blank()
        console.warn("Cancelled.")
        return EXIT_INTERRUPTED
    except KeyboardInterrupt:
        console.blank()
        console.warn("Cancelled.")
        return EXIT_INTERRUPTED
    except CfstNotFoundError as exc:
        console.error(str(exc))
        return EXIT_MISSING_TOOL
    except ScanError as exc:
        # Safety net: the scanner failed for a reason that is not a missing
        # binary (for example a binary this machine cannot execute).
        console.error(str(exc))
        return EXIT_FAILED
