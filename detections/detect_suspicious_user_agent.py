#!/usr/bin/env python3
"""
detect_suspicious_user_agent.py

Detection #2 for SentryLog: non-browser / automation user-agent detection.

Rule: flag any login (user.session.start) whose user-agent string contains a
known automation-tool signature. A login from curl, wget, python-requests, etc.
is almost never a real human -- it means a script or tool is authenticating.

Approach: BLOCKLIST. We match against known-bad agent signatures. Chosen because
this tenant has no legitimate automation to allowlist around. Limitation: only
catches tools on the list, and a careful attacker can spoof a browser UA to evade.
MITRE ATT&CK: T1078 (Valid Accounts) / automated credential use.

Usage:
    python detect_suspicious_user_agent.py attack_burst.csv
"""

import csv
import sys

LOGIN_EVENT = "user.session.start"
UA_FIELD = "client.user_agent.raw_user_agent"

# known automation-tool signatures (matched case-insensitively, as substrings)
BLOCKLIST = [
    "python-requests",
    "curl",
    "wget",
    "go-http-client",
    "postmanruntime",
]


def is_suspicious(user_agent):
    """Return the matched signature if the UA contains a blocklisted tool,
    otherwise None. Lowercased so 'Curl', 'CURL', 'curl' all match."""
    ua = user_agent.lower()
    for sig in BLOCKLIST:
        if sig in ua:
            return sig
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python detect_suspicious_user_agent.py <csv_file>")
        sys.exit(1)

    path = sys.argv[1]

    scanned = 0
    # group suspicious logins per user so we emit ONE alert per user, not one
    # per event. This reduces alert fatigue -- a real SOC wants "maya: 15
    # suspicious logins" as a single actionable item, not 15 identical lines.
    per_user = {}  # user -> {"count": int, "agents": set()}
    with open(path) as f:
        for row in csv.DictReader(f):
            if row["event_type"] != LOGIN_EVENT:
                continue
            scanned += 1
            ua = row.get(UA_FIELD, "")
            match = is_suspicious(ua)
            if match:
                user = row["actor.alternate_id"]
                if user not in per_user:
                    per_user[user] = {"count": 0, "agents": set()}
                per_user[user]["count"] += 1
                per_user[user]["agents"].add(match)

    print(f"Suspicious user-agent detection  (blocklist: {', '.join(BLOCKLIST)})")
    print(f"Scanned {scanned} login events.\n")

    if not per_user:
        print("No suspicious user agents found.")
    else:
        for user, info in per_user.items():
            tools = ", ".join(sorted(info["agents"]))
            print(f"ALERT: {user} -- {info['count']} suspicious-UA logins "
                  f"via {tools}")


if __name__ == "__main__":
    main()
