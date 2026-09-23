from __future__ import annotations
import argparse, json, time
from pathlib import Path
from .core import snapshot, diff, save_json, load_json


def print_changes(changes: dict) -> None:
    labels = [('created','CREATED'),('deleted','DELETED'),('modified','MODIFIED')]
    any_change = False
    for key, label in labels:
        for item in changes[key]:
            any_change = True; print(f'[{label}] {item}')
    for r in changes['renamed']:
        any_change = True; print(f"[RENAMED] {r['from']} -> {r['to']}")
    if not any_change: print('[OK] No integrity changes detected.')


def main(argv=None):
    p = argparse.ArgumentParser(prog='pyfileguard', description='SHA-256 file integrity monitoring for defensive use.')
    sub = p.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('baseline', help='Create a trusted baseline'); b.add_argument('directory'); b.add_argument('-o','--output',default='.pyfileguard-baseline.json')
    c = sub.add_parser('check', help='Compare directory with a baseline'); c.add_argument('directory'); c.add_argument('-b','--baseline',default='.pyfileguard-baseline.json'); c.add_argument('--json',action='store_true')
    m = sub.add_parser('monitor', help='Continuously check for changes'); m.add_argument('directory'); m.add_argument('-b','--baseline',default='.pyfileguard-baseline.json'); m.add_argument('-i','--interval',type=float,default=5.0); m.add_argument('--update-baseline',action='store_true')
    args = p.parse_args(argv)
    root=Path(args.directory); baseline=Path(getattr(args,'baseline',getattr(args,'output','.pyfileguard-baseline.json')))
    if args.cmd=='baseline':
        data=snapshot(root); save_json(data, Path(args.output)); print(f"[+] Baseline saved: {args.output} ({len(data['files'])} files)")
    elif args.cmd=='check':
        changes=diff(load_json(baseline), snapshot(root)); print(json.dumps(changes,indent=2) if args.json else '', end='');
        if not args.json: print_changes(changes)
        return 1 if any(changes.values()) else 0
    else:
        trusted=load_json(baseline); print(f'[+] Monitoring {root.resolve()} every {args.interval:g}s. Ctrl+C to stop.')
        try:
            while True:
                current=snapshot(root); changes=diff(trusted,current)
                if any(changes.values()):
                    print_changes(changes)
                    if args.update_baseline: trusted=current; save_json(trusted,baseline); print('[+] Baseline updated.')
                time.sleep(args.interval)
        except KeyboardInterrupt: print('\n[+] Monitor stopped.')
