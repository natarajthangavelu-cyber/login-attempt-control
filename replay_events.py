#!/usr/bin/env python3
"""Replay a CSV of authentication events (e.g. the task's "Download Login Events"
file) through the guard and report what would have been delayed / locked out.

    python replay_events.py path/to/login_events.csv

Column names are auto-detected (case-insensitive):
    timestamp : timestamp, time, ts, datetime, event_time   (ISO-8601 or epoch seconds)
    username  : username, user, user_id, account, email
    ip        : ip, ip_address, src_ip, source_ip, client_ip
    result    : success, result, status, outcome, event
"""
import csv
import os
import sys
from collections import Counter
from datetime import datetime

from login_guard import GuardConfig, LoginGuard, ManualClock

ALIASES = {
    "ts": ["timestamp", "time", "ts", "datetime", "event_time", "date"],
    "user": ["username", "user", "user_id", "account", "email", "login"],
    "ip": ["ip", "ip_address", "src_ip", "source_ip", "client_ip", "remote_addr"],
    "result": ["success", "result", "status", "outcome", "event", "event_type"],
}
SUCCESS_WORDS = {"1", "true", "yes", "success", "successful", "ok", "pass", "login_success", "succeeded"}


def pick(fieldnames, wanted):
    lower = {f.lower().strip(): f for f in fieldnames}
    for name in ALIASES[wanted]:
        if name in lower:
            return lower[name]
    sys.exit(f"Could not find a '{wanted}' column. Columns found: {fieldnames}\n"
             f"Edit ALIASES in replay_events.py to match your file.")


def parse_ts(value):
    try:
        return float(value)
    except ValueError:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).timestamp()


def main(path):
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        c_ts, c_user, c_ip, c_res = (pick(reader.fieldnames, k) for k in ("ts", "user", "ip", "result"))
        rows = [(parse_ts(r[c_ts]), r[c_user], r[c_ip], r[c_res].strip().lower() in SUCCESS_WORDS) for r in reader]
    rows.sort(key=lambda r: r[0])

    os.makedirs("logs", exist_ok=True)
    audit = "logs/replay_audit.log"
    if os.path.exists(audit):
        os.remove(audit)
    clock = ManualClock(rows[0][0])
    guard = LoginGuard(GuardConfig(), audit_path=audit, clock=clock)

    outcome = Counter()
    for ts, user, ip, ok in rows:
        clock.now = ts
        res = guard.attempt_login(user, "x", ip, lambda u, p, ok=ok: ok)
        if res.success:
            outcome["accepted"] += 1
        elif res.reason == "invalid_credentials":
            outcome["failed (evaluated)"] += 1
        elif res.reason == "delay":
            outcome["rejected by progressive delay"] += 1
        else:
            outcome["rejected by lockout"] += 1
            if ok:
                outcome["  ...of which were genuine successes blocked"] += 1

    locks = [e for e in guard.audit_events if e["event"] == "LOCKOUT_STARTED"]
    print(f"Replayed {len(rows)} events from {path}\n")
    for k, v in outcome.items():
        print(f"  {k:<48}{v:>6}")
    print(f"\nLockouts triggered: {len(locks)}")
    for e in locks:
        print(f"  {e['ts']}  {e['key']:<24} after {e['failures']} failures, until {e['unlock_at']}")
    print(f"\nAudit trail written to {audit}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
