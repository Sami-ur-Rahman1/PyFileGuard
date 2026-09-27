from __future__ import annotations

import argparse
import getpass
import time
from dataclasses import replace
from pathlib import Path

from . import __version__
from .core import *
from .database import add_event, query_events
from .profiles import save_profile, list_profiles, load_profile, delete_profile
from .reporting import export_events
from .severity import classify


BANNER = f"""
========================================================
                     PyFileGuard
              A FortiX CyberTech Product

               Defend. Secure. Fortify.
                    Version {__version__}
========================================================"""


def paths(s):
    return [x.strip() for x in s.split(";") if x.strip()]


def sev(e):
    return replace(e, severity=classify(e.path, e.kind))


def print_event(root, e):
    e = sev(e)

    target = (
        f"{e.old_path} -> {e.path}"
        if e.kind == "RENAMED"
        else e.path
    )

    print(
        f"[{e.severity:<8}] [{e.kind}] {target}"
        + (f"  ({root})" if root else "")
    )

    return e


def create_baseline(dirs, out, ignores=None, protect=False):
    b = build_baseline(dirs, ignores)

    if protect:
        k = getpass.getpass("Baseline protection key: ")
        k2 = getpass.getpass("Confirm key: ")

        if not k or k != k2:
            raise ValueError(
                "Protection keys do not match or are empty."
            )

        b = sign_baseline(b, k)

    save_baseline(b, out)

    print(
        f"[+] Baseline saved: {Path(out).expanduser()} "
        f"({sum(map(len, b['directories'].values()))} files)"
    )


def authenticate(b):
    if b.get("integrity"):
        k = getpass.getpass("Baseline protection key: ")

        if not verify_baseline(b, k):
            print(
                "[CRITICAL] Baseline integrity verification failed."
            )
            return False

        print("[+] Baseline integrity verified.")

    return True


def check_integrity(bp, ignores=None):
    b = load_baseline(bp)

    if not authenticate(b):
        return 2

    ev = compare_baseline(b, ignores)

    if not ev:
        print("[OK] No integrity changes detected.")
        return 0

    for r, e in ev:
        print_event(r, e)

    return 1


def monitor(bp, interval=5, ignores=None):
    b = load_baseline(bp)

    if not authenticate(b):
        return 2

    roots = list(b["directories"])

    merged = (
        list(b.get("ignores", []))
        + list(ignores or [])
    )

    previous = {
        r: scan_directory(r, merged)
        for r in roots
    }

    print(
        f"[+] Monitoring {len(roots)} "
        f"director{'y' if len(roots) == 1 else 'ies'} "
        f"every {interval}s. Ctrl+C to stop."
    )

    try:
        while True:
            time.sleep(interval)

            for r in roots:
                cur = scan_directory(r, merged)

                for e in compare_snapshots(previous[r], cur):
                    e = print_event(r, e)
                    add_event(e, r)

                previous[r] = cur

    except KeyboardInterrupt:
        print("\n[+] Monitor stopped.")

    return 0


def show_history(event=None, severity=None, text=None, limit=100):
    rows = query_events(event, severity, text, limit)

    if not rows:
        print("No events found.")
        return

    print(
        "ID       TIME                       "
        "SEVERITY   EVENT       PATH"
    )
    print("-" * 100)

    for i, ts, ev, s, r, p, o in rows:
        target = f"{o} -> {p}" if o else p

        print(
            f"EVT-{i:04d} "
            f"{ts:<25} "
            f"{s:<10} "
            f"{ev:<11} "
            f"{target}"
        )


def interactive():
    while True:
        print(BANNER)

        print(
            """
 [1] Create Baseline
 [2] Check Integrity
 [3] Start Monitor Mode
 [4] Event History
 [5] Manage Profiles
 [6] Export Reports
 [7] About PyFileGuard
 [0] Exit"""
        )

        c = input("\n Select option > ").strip()

        try:
            if c == "1":
                d = paths(
                    input(
                        "Directories "
                        "(separate multiple paths with ;): "
                    )
                )

                o = (
                    input(
                        "Baseline output "
                        "[.pyfileguard-baseline.json]: "
                    ).strip()
                    or ".pyfileguard-baseline.json"
                )

                ig = paths(
                    input(
                        "Custom ignore patterns "
                        "(optional; separate with ;): "
                    )
                )

                pr = (
                    input(
                        "Protect baseline with HMAC key? [y/N]: "
                    ).lower()
                    == "y"
                )

                create_baseline(d, o, ig, pr)

            elif c == "2":
                check_integrity(
                    input(
                        "Baseline path "
                        "[.pyfileguard-baseline.json]: "
                    ).strip()
                    or ".pyfileguard-baseline.json"
                )

            elif c == "3":
                monitor(
                    input(
                        "Baseline path "
                        "[.pyfileguard-baseline.json]: "
                    ).strip()
                    or ".pyfileguard-baseline.json",
                    int(
                        input(
                            "Scan interval [5]: "
                        ).strip()
                        or 5
                    ),
                )

            elif c == "4":
                show_history(
                    input(
                        "Event filter (optional): "
                    ).strip()
                    or None,
                    input(
                        "Severity filter (optional): "
                    ).strip()
                    or None,
                    input(
                        "Path contains (optional): "
                    ).strip()
                    or None,
                )

            elif c == "5":
                print(
                    "\n [1] Create/Update Profile"
                    "\n [2] List Profiles"
                    "\n [3] Delete Profile"
                    "\n [0] Back"
                )

                x = input(" Select option > ").strip()

                if x == "1":
                    result = save_profile(
                        input("Profile name: "),
                        paths(
                            input(
                                "Directories (; separated): "
                            )
                        ),
                        input("Baseline path: "),
                        int(
                            input(
                                "Interval [5]: "
                            )
                            or 5
                        ),
                        paths(
                            input(
                                "Ignore patterns "
                                "(optional): "
                            )
                        ),
                    )

                    print(
                        f"[+] Profile saved: {result}"
                    )

                elif x == "2":
                    print(
                        "\n".join(
                            "- " + p.stem
                            for p in list_profiles()
                        )
                        or "No profiles found."
                    )

                elif x == "3":
                    print(
                        "[+] Deleted."
                        if delete_profile(
                            input("Profile name: ")
                        )
                        else "Profile not found."
                    )

            elif c == "6":
                f = (
                    input("Format [json/csv]: ").lower()
                    or "json"
                )

                o = (
                    input(
                        f"Output [pyfileguard-report.{f}]: "
                    ).strip()
                    or f"pyfileguard-report.{f}"
                )

                print(
                    f"[+] Exported "
                    f"{export_events(o, f)} "
                    f"events to {o}"
                )

            elif c == "7":
                print(
                    f"\nPyFileGuard v{__version__}"
                    "\nA FortiX CyberTech Product"
                    "\n\nDefend. Secure. Fortify."
                )

            elif c == "0":
                print("Goodbye.")
                return 0

            else:
                print("Invalid option.")

        except (
            ValueError,
            OSError,
            FileNotFoundError,
        ) as e:
            print(f"[ERROR] {e}")

        input("\nPress Enter to continue...")


# ---------------------------------------------------------
# Profile argument resolution
# ---------------------------------------------------------

def resolve_check_args(args):
    """
    Resolve baseline and ignore rules for the check command.

    When --profile is supplied, settings are loaded from the
    saved profile. Additional command-line ignore patterns
    are appended to the profile's ignore rules.
    """

    if not args.profile:
        return args.baseline, list(args.ignore or [])

    profile = load_profile(args.profile)

    baseline = profile["baseline"]

    ignores = (
        list(profile.get("ignores", []))
        + list(args.ignore or [])
    )

    return baseline, ignores


def resolve_monitor_args(args):
    """
    Resolve baseline, interval and ignore rules for monitor.

    Explicit command-line options override profile settings.
    """

    if not args.profile:
        interval = (
            args.interval
            if args.interval is not None
            else 5
        )

        return (
            args.baseline,
            max(1, interval),
            list(args.ignore or []),
        )

    profile = load_profile(args.profile)

    baseline = profile["baseline"]

    interval = (
        args.interval
        if args.interval is not None
        else int(profile.get("interval", 5))
    )

    ignores = (
        list(profile.get("ignores", []))
        + list(args.ignore or [])
    )

    return baseline, max(1, interval), ignores


def parser():
    p = argparse.ArgumentParser(
        description=(
            "SHA-256 file integrity monitoring "
            "for defensive use."
        )
    )

    p.add_argument(
        "--version",
        action="version",
        version=f"PyFileGuard {__version__}",
    )

    s = p.add_subparsers(dest="command")

    # Baseline
    b = s.add_parser("baseline")

    b.add_argument(
        "directories",
        nargs="+",
    )

    b.add_argument(
        "-o",
        "--output",
        default=".pyfileguard-baseline.json",
    )

    b.add_argument(
        "--ignore",
        action="append",
        default=[],
    )

    b.add_argument(
        "--protect",
        action="store_true",
    )

    # Check
    c = s.add_parser("check")

    cg = c.add_mutually_exclusive_group(
        required=True
    )

    cg.add_argument(
        "-b",
        "--baseline",
    )

    cg.add_argument(
        "--profile",
    )

    c.add_argument(
        "--ignore",
        action="append",
        default=[],
    )

    # Monitor
    m = s.add_parser("monitor")

    mg = m.add_mutually_exclusive_group(
        required=True
    )

    mg.add_argument(
        "-b",
        "--baseline",
    )

    mg.add_argument(
        "--profile",
    )

    m.add_argument(
        "--interval",
        type=int,
        default=None,
    )

    m.add_argument(
        "--ignore",
        action="append",
        default=[],
    )

    # History
    h = s.add_parser("history")

    h.add_argument("--event")
    h.add_argument("--severity")
    h.add_argument("--path")

    h.add_argument(
        "--limit",
        type=int,
        default=100,
    )

    # Export
    x = s.add_parser("export")

    x.add_argument("output")

    x.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
    )

    x.add_argument("--event")
    x.add_argument("--severity")
    x.add_argument("--path")

    # Profiles
    pr = s.add_parser("profile")

    pr.add_argument(
        "action",
        choices=[
            "list",
            "show",
            "delete",
        ],
    )

    pr.add_argument(
        "name",
        nargs="?",
    )

    return p


def main(argv=None):
    p = parser()
    a = p.parse_args(argv)

    if not a.command:
        return interactive()

    if a.command == "baseline":
        create_baseline(
            a.directories,
            a.output,
            a.ignore,
            a.protect,
        )
        return 0

    if a.command == "check":
        baseline, ignores = resolve_check_args(a)

        return check_integrity(
            baseline,
            ignores,
        )

    if a.command == "monitor":
        baseline, interval, ignores = (
            resolve_monitor_args(a)
        )

        return monitor(
            baseline,
            interval,
            ignores,
        )

    if a.command == "history":
        show_history(
            a.event,
            a.severity,
            a.path,
            a.limit,
        )
        return 0

    if a.command == "export":
        count = export_events(
            a.output,
            a.format,
            event=a.event,
            severity=a.severity,
            path_text=a.path,
        )

        print(
            f"[+] Exported {count} events "
            f"to {a.output}"
        )

        return 0

    if a.command == "profile":
        if a.action == "list":
            for x in list_profiles():
                print(x.stem)

        elif not a.name:
            p.error(
                "profile show/delete requires a name"
            )

        elif a.action == "show":
            print(load_profile(a.name))

        else:
            print(
                "Deleted."
                if delete_profile(a.name)
                else "Profile not found."
            )

        return 0