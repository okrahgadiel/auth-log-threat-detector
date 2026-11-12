"""CLI: python -m detector sample_data/signins.jsonl sample_data/auth.log"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .events import load_events
from .rules import Config, detect

ICON = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]", "low": "[LOW ]"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Detect identity attacks in authentication logs.")
    ap.add_argument("logs", nargs="+", type=Path, help="Sign-in logs (.jsonl) and/or sshd auth.log files")
    ap.add_argument("--json-out", type=Path, help="Write alerts as JSON Lines (e.g. for SIEM ingestion)")
    ap.add_argument("--brute-force-threshold", type=int, default=Config.brute_force_threshold)
    ap.add_argument("--spray-users", type=int, default=Config.spray_user_threshold)
    args = ap.parse_args(argv)

    cfg = Config(brute_force_threshold=args.brute_force_threshold, spray_user_threshold=args.spray_users)
    events = load_events(args.logs)
    alerts = detect(events, cfg)

    print(f"Analyzed {len(events)} events from {len(args.logs)} file(s); {len(alerts)} alert(s)\n")
    for a in alerts:
        print(f"{ICON[a.severity]} {a.rule:<27} {a.technique:<10} user={(a.user if len(a.user) <= 28 else a.user[:25] + '...'):<28} ip={a.src_ip}")
        print(f"       {a.first_seen:%Y-%m-%d %H:%M} | {a.detail}")
    counts = Counter(a.severity for a in alerts)
    print("\nSummary: " + ", ".join(f"{s}={counts.get(s, 0)}" for s in ("critical", "high", "medium", "low")))

    if args.json_out:
        with open(args.json_out, "w") as fh:
            for a in alerts:
                fh.write(json.dumps(a.to_dict()) + "\n")
        print(f"Alerts written to {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
