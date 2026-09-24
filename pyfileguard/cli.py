from __future__ import annotations
import argparse, json, time
from pathlib import Path
from . import __version__
from .core import diff,get_events,has_changes,load_json,log_changes,save_json,snapshot,utc_now

DEFAULT_BASELINE=".pyfileguard-baseline.json"
DEFAULT_DB=str(Path.home()/".pyfileguard"/"events.db")

def print_changes(c,timestamp=False):
    prefix=f"{utc_now()}  " if timestamp else ""
    if not has_changes(c): print(f"{prefix}[OK] No integrity changes detected."); return
    for p in c["created"]: print(f"{prefix}[CREATED] {p}")
    for p in c["deleted"]: print(f"{prefix}[DELETED] {p}")
    for p in c["modified"]: print(f"{prefix}[MODIFIED] {p}")
    for r in c["renamed"]: print(f"{prefix}[RENAMED] {r['from']} -> {r['to']}")

def _path(s): return input(s).strip().strip('"').strip("'")
def _pause(): input("\nPress Enter to continue...")

def menu():
    while True:
        print("\n"+"="*52+f"\n{'PyFileGuard v'+__version__:^52}\n{'File Integrity Monitor':^52}\n"+"="*52)
        print("\n [1] Create Baseline\n [2] Check Integrity\n [3] Start Monitor Mode\n [4] View Event History\n [5] Help\n [0] Exit\n")
        ch=input(" Select option > ").strip()
        try:
            if ch=="1":
                root=_path(" Directory path > "); out=_path(f" Baseline output [{DEFAULT_BASELINE}] > ") or DEFAULT_BASELINE
                s=snapshot(root); save_json(s,out); print(f"\n[+] Baseline saved: {out} ({len(s['files'])} files)"); _pause()
            elif ch=="2":
                root=_path(" Directory path > "); base=_path(f" Baseline path [{DEFAULT_BASELINE}] > ") or DEFAULT_BASELINE
                print(); print_changes(diff(load_json(base),snapshot(root))); _pause()
            elif ch=="3":
                root=_path(" Directory path > "); base=_path(f" Baseline path [{DEFAULT_BASELINE}] > ") or DEFAULT_BASELINE
                interval=float(input(" Scan interval in seconds [5] > ").strip() or "5")
                monitor(root,base,interval,DEFAULT_DB,False); _pause()
            elif ch=="4":
                rows=get_events(DEFAULT_DB,50); print("\nID      TIME                       EVENT       PATH")
                print("-"*85)
                if not rows: print("No events recorded.")
                for e in rows:
                    p=e["path"]+(f" -> {e['new_path']}" if e["new_path"] else "")
                    print(f"EVT-{e['id']:04d} {e['timestamp']:<26} {e['event_type']:<11} {p}")
                _pause()
            elif ch=="5":
                print("\nPyFileGuard detects CREATED, DELETED, MODIFIED and inferred RENAMED files.\n"
                      "Monitor Mode reports new filesystem events once while keeping the trusted baseline unchanged.\n"
                      "CLI commands remain available: baseline, check, monitor and history."); _pause()
            elif ch=="0": print("Goodbye."); return 0
            else: print("[!] Invalid option.")
        except KeyboardInterrupt: print("\n[+] Operation cancelled.")
        except Exception as e: print(f"\n[!] {e}"); _pause()

def monitor(root,base,interval,db,update):
    if interval<=0: raise ValueError("Interval must be greater than 0.")
    trusted=load_json(base); previous=snapshot(root)
    print(f"[+] Monitoring {Path(root).expanduser().resolve()} every {interval:g}s. Ctrl+C to stop.")
    initial=diff(trusted,previous)
    if has_changes(initial):
        print("[!] Current directory already differs from the trusted baseline:")
        print_changes(initial,True)
    try:
        while True:
            time.sleep(interval); current=snapshot(root)
            events=diff(previous,current)  # v0.2 fix: compare consecutive scans
            if has_changes(events):
                print_changes(events,True); log_changes(db,events,root)
                if update: trusted=current; save_json(trusted,base)
            previous=current
    except KeyboardInterrupt: print("\n[+] Monitor stopped.")
    return 0

def parser():
    p=argparse.ArgumentParser(description="SHA-256 file integrity monitoring for defensive use.")
    p.add_argument("--version", action="version", version=f"PyFileGuard {__version__}")
    s=p.add_subparsers(dest="command")
    b=s.add_parser("baseline",help="Create a trusted baseline"); b.add_argument("directory"); b.add_argument("-o","--output",default=DEFAULT_BASELINE)
    c=s.add_parser("check",help="Compare directory with a baseline"); c.add_argument("directory"); c.add_argument("-b","--baseline",default=DEFAULT_BASELINE); c.add_argument("--json",action="store_true")
    m=s.add_parser("monitor",help="Continuously check for changes"); m.add_argument("directory"); m.add_argument("-b","--baseline",default=DEFAULT_BASELINE); m.add_argument("-i","--interval",type=float,default=5); m.add_argument("--db",default=DEFAULT_DB); m.add_argument("--update-baseline",action="store_true")
    h=s.add_parser("history",help="Show recorded monitor events"); h.add_argument("--db",default=DEFAULT_DB); h.add_argument("-n","--limit",type=int,default=50)
    return p

def main(argv=None):
    p=parser(); a=p.parse_args(argv)
    if a.command is None: return menu()
    try:
        if a.command=="baseline":
            s=snapshot(a.directory); save_json(s,a.output); print(f"[+] Baseline saved: {a.output} ({len(s['files'])} files)"); return 0
        if a.command=="check":
            c=diff(load_json(a.baseline),snapshot(a.directory))
            print(json.dumps(c,indent=2)) if a.json else print_changes(c)
            return 1 if has_changes(c) else 0
        if a.command=="monitor": return monitor(a.directory,a.baseline,a.interval,a.db,a.update_baseline)
        if a.command=="history":
            rows=get_events(a.db,a.limit)
            if not rows: print("[OK] No events recorded."); return 0
            for e in rows:
                target=f" -> {e['new_path']}" if e["new_path"] else ""
                print(f"EVT-{e['id']:04d} {e['timestamp']} [{e['event_type']}] {e['path']}{target}")
            return 0
    except (OSError,ValueError,json.JSONDecodeError) as e: p.error(str(e))
    return 0
