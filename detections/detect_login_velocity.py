#!/usr/bin/env python3
"""
detect_login_velocity.py

Detection #1 for SentryLog: login velocity / burst detection.

Rule: if a single user produces >= 6 login events (user.session.start)
within any 5-second window, flag that user as suspicious.

Why: a human cannot log in 6 times in 5 seconds. That density means
automation -- credential stuffing, session abuse, or a script.

Usage:
    python detect_login_velocity.py attack_burst.csv
"""

import csv
import sys
from datetime import datetime, timedelta
from collections import defaultdict

# --- the two thresholds you chose ---
N = 6        # how many logins
T = 15       # within how many seconds
LOGIN_EVENT = "user.session.start"


def parse_ts(value):
    """Turn Okta's '2026-06-24T16:21:44.685Z' string into a datetime object
    so we can do time math on it."""
    # strip the trailing 'Z' and parse with milliseconds
    return datetime.strptime(value.replace("Z", ""), "%Y-%m-%dT%H:%M:%S.%f")


def main():
    if len(sys.argv) < 2:
        print("Usage: python detect_login_velocity.py <csv_file>")
        sys.exit(1)

    path = sys.argv[1]

    # Step 1: read the CSV and keep only login events.
    logins_by_user = defaultdict(list)
    with open(path) as f:
        for row in csv.DictReader(f):
            if row["event_type"] == LOGIN_EVENT:
                user = row["actor.alternate_id"]
                logins_by_user[user].append(parse_ts(row["timestamp"]))

    # Step 2: for each user, look for a burst.
    alerts = []
    for user, times in logins_by_user.items():
        times.sort()  # logins must be in time order to slide a window

        # sliding window: for each login, count how many logins fall
        # within T seconds AFTER it (including itself).
        for i, start in enumerate(times):
            window_end = start + timedelta(seconds=T)
            count = sum(1 for t in times[i:] if t <= window_end)
            if count >= N:
                alerts.append((user, start, count))
                break  # one alert per user is enough; stop scanning them

    # Step 3: report.
    print(f"Login-velocity detection  (N={N} logins within T={T}s)")
    print(f"Scanned {sum(len(v) for v in logins_by_user.values())} login events "
          f"across {len(logins_by_user)} users.\n")

    if not alerts:
        print("No bursts detected.")
    else:
        for user, when, count in alerts:
            print(f"ALERT: {user} had {count} logins starting {when} "
                  f"(>= {N} within {T}s)")


if __name__ == "__main__":
    main()
