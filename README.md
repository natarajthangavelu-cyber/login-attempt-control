# Login Attempt Control System

Brute-force protection for a login system: failed-login counters, progressive delay,
15-minute temporary lockouts, and an audit log. Pure Python standard library, no installs needed.

## How it maps to the task

| Task step | Where |
|---|---|
| 1. Track failed attempts by IP / username in memory or database | `login_guard/guard.py` – SQLite (`:memory:` or a file); keys `user:<name>` and `ip:<addr>` |
| 2. Progressive delay or 15-minute lockout after 5 consecutive failures | `GuardConfig` – delay 1s, 2s, 4s, 8s… then lockout on the 5th failure (900 s) |
| 3. Log lockout events for admin audit | `logs/lockout_audit.log` (JSON lines: `LOGIN_FAILED`, `LOCKOUT_STARTED`, `LOGIN_BLOCKED`, `LOGIN_DELAYED`, `LOCKOUT_EXPIRED`, `ADMIN_UNLOCK`, `LOGIN_SUCCESS`) |
| 4. Test against a simulated brute-force loop | `simulate.py` and `tests/test_guard.py` |

## Requirements

Python 3.9+ (nothing to `pip install`).

## Run it

```bash
# 1. Unit tests (15 tests)
python -m unittest -v

# 2. Simulated brute-force attack (writes the proof logs, exit code 0 = all checks passed)
python simulate.py

# 3. Save the test output as submission proof
python -m unittest -v > logs/unit_tests.log 2>&1
python simulate.py                       # writes logs/test_run.log + logs/lockout_audit.log

# 4. Replay the task's "Download Login Events" CSV
python replay_events.py path/to/login_events.csv
python replay_events.py sample_data/login_events_sample.csv   # bundled sample
```

Windows: use `python` or `py`; on macOS/Linux use `python3` if `python` is not found.

`replay_events.py` auto-detects column names (timestamp / username / ip / success-or-result).
If your CSV uses different names, add them to the `ALIASES` dict at the top of the file.

## What the simulation proves (`logs/test_run.log`)

1. A 60-guess brute-force loop against one account is stopped: delays throttle it, the 5th failure locks the account, and every later guess is rejected without being evaluated.
2. The **correct** password is also refused during the lockout.
3. Other users are not affected.
4. The lockout expires after 15 minutes and the user can log in again.
5. Credential spraying (one IP, 30 usernames) triggers an IP lockout after 20 failures.
6. A legitimate user with a few typos is not locked out (a successful login resets the counter).

## Use it in your own app

```python
from login_guard import LoginGuard, GuardConfig

guard = LoginGuard(GuardConfig(), db_path="guard_state.db", audit_path="logs/lockout_audit.log")

result = guard.attempt_login(username, password, client_ip, authenticate=my_check_password)
if result.success:
    ...
else:
    return error(result.message, retry_after=result.retry_after)   # HTTP 429 for delay/lockout
```

`authenticate(username, password) -> bool` is your own credential check. It is **never called**
while the account or IP is locked.

## Design notes

* **Consecutive failures** reset on a successful login; stale failures expire after `failure_window_seconds`.
* **Delayed attempts don't count** as failures, so an attacker can't extend someone's lockout by hammering.
* **No account enumeration**: unknown usernames are throttled exactly like real ones, and `LoginResult.message` is generic.
* **IP counter** (default 20) is higher than the user counter because many users can share one NAT address.
* **Passwords are never written to any log.**
* Behind a proxy or load balancer, pass the real client IP (e.g. from a trusted `X-Forwarded-For`), not the proxy's.
* A lockout can be used to deny service to a victim account; the IP counter, the 15-minute expiry and `guard.unlock(user)` limit that.

## Layout

```
login_guard/guard.py          core logic
tests/test_guard.py           unit tests
simulate.py                   brute-force simulation (generates proof logs)
replay_events.py              replay a CSV of login events
sample_data/                  small synthetic CSV
logs/                         generated proof: test_run.log, lockout_audit.log, unit_tests.log, replay_*.log
```
