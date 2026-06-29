# SentryLog — Identity Attack Detection

Detection-as-code for identity attacks against Okta. A small, version-controlled
set of detections that read Okta System Log telemetry and flag signs of account
abuse — written in Python, expressed as portable Sigma rules, and mapped to MITRE
ATT&CK.

## The problem

Every identity provider logs every login, MFA prompt, and admin action. Attackers
hide inside that volume — a stolen session or a scripted login looks almost like
normal activity. The defender's job is to write logic that catches the malicious
events *without* drowning analysts in false positives. SentryLog is a focused
demonstration of that skill at the identity layer.

## Detections

| # | Detection | What it catches | MITRE ATT&CK |
|---|-----------|-----------------|--------------|
| 1 | Login velocity / burst | ≥6 logins by one user within 15 seconds — automated credential abuse | T1110 (Brute Force) |
| 2 | Suspicious user agent | Logins from non-browser automation tools (python-requests, curl, wget, etc.) | T1078 (Valid Accounts) |

Each detection exists as **both** a Python script (readable, runnable) and a
**Sigma rule** (portable to Splunk, Elastic, and other SIEMs).

## How it works

1. **Telemetry** — real Okta System Log events were exported from a personal
   developer tenant as CSV.
2. **Attack emulation** — a controlled burst of scripted logins was generated
   against a test user to produce labeled malicious activity. (Benign baseline =
   normal account activity in the same tenant.)
3. **Detection** — each Python detection reads the CSV, applies its logic, and
   emits alerts. Alerts are deduplicated per user to reduce alert fatigue.
4. **Measurement** — detections are scored with precision/recall against the
   labeled data (see Results).

> Note on methodology: the malicious dataset is *emulated* telemetry modeled on
> documented attack signatures, not captured from a live attack. This is standard
> practice for detection efficacy work when live attack data isn't available.


> **Data handling:** raw telemetry is never committed. The included
> `data/attack_burst_sample.csv` is sanitized — real IPs and the real admin
> username were replaced with documentation-safe values. Raw exports are
> `.gitignore`d.

## Results

On a controlled labeled dataset (1 attacker account, 1 benign account):

- **Precision: 1.00** — every alert corresponded to the real attacker; no false positives.
- **Recall: 1.00** — the attacker was caught by both detections; none missed.

**A 100% score here doesn't mean the detection is "good" — it means the logic
works.** The test only had 2 users: one obvious attacker and one obvious normal
user. With a test that easy, any working detection scores 100%. It proves the rule
fires when it should; it does *not* prove a real-world false-positive rate.

A meaningful score would require testing against many users, including the tricky
ones that look like attackers but aren't — service accounts that log in
constantly, or clients stuck in fast SSO retry loops. Those borderline cases are
where a detection actually gets tested, and this dataset doesn't have them yet.
Building a larger, messier benign baseline to surface real false positives is the
planned next step.

## Limitations

- **Login velocity (Detection #1):** the 15-second window only catches fast
  bursts. A low-and-slow attacker who spaces logins out (one every 30+ seconds)
  stays under the threshold and evades detection.
- **User-agent blocklist (Detection #2):** only catches tools on the list, and
  more critically, a sophisticated attacker can spoof a legitimate browser
  user-agent to defeat it entirely.
- **Dataset:** small and synthetic — a single emulated attack against one test
  user, in one tenant, from one geographic location. Real environments have far
  more volume, variety, and noise.
- **Sigma portability:** Detection #1 uses a correlation rule (time-window count)
  that not all SIEM backends support, unlike the simple field-match in
  Detection #2.

## What I learned / key design decisions

- **Detection-as-code workflow:** how a detection goes from idea → Python logic →
  portable Sigma rule that a SIEM can run, mapped to MITRE ATT&CK. Writing the
  logic in Python first made the Sigma rule easier to reason about.
- **Threshold tuning is a judgment call.** My first velocity window (5s) missed
  the burst because the logins were paced ~1.6s apart. Widening to 15s caught it —
  but I had to reason about *which* attack I was trying to catch, not just pick a
  number. The threshold trades off catching slow attacks against false positives.
- **Blocklist vs. allowlist.** I chose a user-agent blocklist because this tenant
  has no legitimate automation to allowlist around. In a real enterprise with many
  integrations, I'd pair it with an allowlist-based hunt — the right choice depends
  on the environment.
- **Alert fatigue is real.** I deduplicated alerts to one-per-user-with-a-count
  instead of one-per-event, because a SOC analyst wants a single actionable item,
  not 15 identical lines.
- **A perfect score can be meaningless.** 100% precision/recall on a 2-user test
  only proved the logic fires — not that the detection is good. Understanding that
  gap mattered more than the number.

## Repo structure

```
sentrylog/
├── README.md
├── detections/
│   ├── detect_login_velocity.py        # Detection #1 (Python)
│   └── detect_suspicious_user_agent.py  # Detection #2 (Python)
├── sigma/
│   ├── login_velocity.yml               # Detection #1 (Sigma correlation rule)
│   └── suspicious_user_agent.yml        # Detection #2 (Sigma rule)
└── data/
    └── attack_burst_sample.csv                 # labeled Okta telemetry (benign + emulated attack)
```

## Running it

```
python detections/detect_login_velocity.py data/attack_burst_sample.csv
python detections/detect_suspicious_user_agent.py data/attack_burst_sample.csv
```
