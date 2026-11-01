#!/usr/bin/env python3
"""Simulated brute-force run. Produces the proof logs:
    logs/test_run.log        human-readable timeline + PASS/FAIL checks
    logs/lockout_audit.log   JSON-lines security audit trail
Uses a fake clock, so the whole 15-minute lockout runs in a fraction of a second.
Exit code is 0 only if every check passes.
"""
import os
import sys

from login_guard import GuardConfig, LoginGuard, ManualClock

LOG_DIR = "logs"
RUN_LOG = os.path.join(LOG_DIR, "test_run.log")
AUDIT_LOG = os.path.join(LOG_DIR, "lockout_audit.log")

USERS = {"alice": "C0rrect-Horse!", "bob": "hunter2-but-longer"}
ATTACKER, SPRAYER, BOB_IP = "203.0.113.50", "192.0.2.99", "198.51.100.7"


def authenticate(username, password):
    return USERS.get(username) == password


class Report:
    def __init__(self, path):
        self.fh = open(path, "w", encoding="utf-8")
        self.passed = self.failed = 0

    def say(self, text=""):
        print(text)
        self.fh.write(text + "\n")

    def check(self, label, condition):
        self.passed += bool(condition)
        self.failed += not condition
        self.say(f"  [{'PASS' if condition else 'FAIL'}] {label}")


def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    if os.path.exists(AUDIT_LOG):
        os.remove(AUDIT_LOG)

    clock = ManualClock()
    t0 = clock()
    guard = LoginGuard(GuardConfig(), audit_path=AUDIT_LOG, clock=clock)
    rep = Report(RUN_LOG)

    def attempt(user, pw, ip):
        res = guard.attempt_login(user, pw, ip, authenticate)
        status = "ACCEPTED" if res.success else f"REJECTED ({res.reason})"
        extra = f"  retry_after={res.retry_after:.0f}s" if res.retry_after else ""
        rep.say(f"  [t+{clock() - t0:7.1f}s] {user:<7} {ip:<15} pw={pw:<16} -> {status}{extra}")
        return res

    def events(name, **match):
        return [e for e in guard.audit_events
                if e["event"] == name and all(e.get(k) == v for k, v in match.items())]

    rep.say("=" * 78)
    rep.say("LOGIN ATTEMPT CONTROL - SIMULATED BRUTE-FORCE TEST")
    rep.say(f"Config: {guard.config}")
    rep.say("=" * 78)

    # ---- 1 ------------------------------------------------------------------
    rep.say("\nSCENARIO 1: brute-force loop against 'alice' (60 guesses, one every 0.5s)")
    for i in range(60):
        attempt("alice", f"guess{i:02d}", ATTACKER)
        clock.advance(0.5)
    rep.say("")
    rep.check("exactly 5 failed attempts were evaluated before lockout",
              len(events("LOGIN_FAILED", username="alice")) == 5)
    rep.check("account lockout started once for user:alice",
              len(events("LOCKOUT_STARTED", key="user:alice")) == 1)
    rep.check("progressive delay rejected fast retries before the lockout",
              len(events("LOGIN_DELAYED", username="alice")) > 0)
    rep.check("remaining guesses were blocked by the lockout (not evaluated)",
              len(events("LOGIN_BLOCKED", username="alice")) > 0)

    # ---- 2 ------------------------------------------------------------------
    rep.say("\nSCENARIO 2: correct password is still refused while locked")
    res = attempt("alice", USERS["alice"], ATTACKER)
    rep.check("correct password rejected during lockout", not res.success and res.reason == "lockout")
    wait = res.retry_after

    # ---- 3 ------------------------------------------------------------------
    rep.say("\nSCENARIO 3: another user is unaffected by alice's lockout")
    res = attempt("bob", USERS["bob"], BOB_IP)
    rep.check("bob can log in normally", res.success)

    # ---- 4 ------------------------------------------------------------------
    rep.say(f"\nSCENARIO 4: lockout expires after ~{wait / 60:.0f} minutes")
    clock.advance(wait - 1)
    res = attempt("alice", USERS["alice"], BOB_IP)
    rep.check("still locked 1 second before expiry", res.reason == "lockout")
    clock.advance(2)
    res = attempt("alice", USERS["alice"], BOB_IP)
    rep.check("alice can log in after lockout expires", res.success)
    rep.check("LOCKOUT_EXPIRED audit event written", len(events("LOCKOUT_EXPIRED", key="user:alice")) == 1)

    # ---- 5 ------------------------------------------------------------------
    rep.say("\nSCENARIO 5: credential spraying - one IP tries 30 different usernames")
    for i in range(30):
        attempt(f"user{i:02d}", "Password1!", SPRAYER)
        clock.advance(0.1)
    rep.say("")
    rep.check("IP lockout started once after 20 failures",
              len(events("LOCKOUT_STARTED", key=f"ip:{SPRAYER}")) == 1)
    rep.check("attempts 21-30 from that IP were blocked",
              len(events("LOGIN_BLOCKED", ip=SPRAYER)) == 10)
    res = attempt("bob", USERS["bob"], SPRAYER)
    rep.check("even a valid login from the locked IP is refused", not res.success)

    # ---- 6 ------------------------------------------------------------------
    rep.say("\nSCENARIO 6: legitimate typos do not lock out (counter resets on success)")
    clock.advance(1000)  # let the spray lockout lapse

    def patient(user, pw, ip):  # waits out any progressive delay first, like a human would
        d = guard.check(user, ip)
        if not d.allowed and d.reason == "delay":
            clock.advance(d.retry_after + 0.01)
        return attempt(user, pw, ip)

    patient("bob", "typo1", BOB_IP)
    patient("bob", "typo2", BOB_IP)
    res = patient("bob", USERS["bob"], BOB_IP)
    rep.check("bob logs in after two typos", res.success)
    for i in range(4):
        patient("bob", f"typo-again{i}", BOB_IP)
    rep.check("4 more failures after a success do NOT lock bob (needs 5 consecutive)",
              guard.check("bob", BOB_IP).reason != "lockout")

    rep.say("\n" + "=" * 78)
    rep.say(f"RESULT: {rep.passed} passed, {rep.failed} failed")
    rep.say(f"Audit log: {AUDIT_LOG} ({sum(1 for _ in open(AUDIT_LOG))} events)")
    rep.say("=" * 78)
    rep.fh.close()
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
