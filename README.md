# Auth Log Threat Detector

![CI](https://github.com/okrahgadiel/auth-log-threat-detector/actions/workflows/ci.yml/badge.svg)

A lightweight, SIEM-style detection engine for **identity attacks**. It ingests Microsoft Entra ID (Azure AD) sign-in logs and Linux `sshd` auth logs, normalizes them into one event schema, and runs sliding-window detection rules mapped to **MITRE ATT&CK**. Alerts print to the console and can be written as JSON Lines for SIEM or SOAR ingestion.

## Detections

| Rule | ATT&CK | Severity | Logic |
|---|---|---|---|
| `SUCCESS_AFTER_BRUTE_FORCE` | T1078 Valid Accounts | Critical | A successful login from an IP that was brute-forcing that same account (likely account takeover) |
| `MFA_FATIGUE` | T1621 MFA Request Generation | High → Critical | ≥5 MFA push denials in 15 min; escalated if the user then approves |
| `BRUTE_FORCE` | T1110.001 Password Guessing | High | ≥8 failures for one user from one IP within 10 min |
| `PASSWORD_SPRAY` | T1110.003 Password Spraying | High | One IP failing against ≥6 **distinct** accounts within 30 min |
| `IMPOSSIBLE_TRAVEL` | T1078 Valid Accounts | High | Consecutive successful logins whose implied speed exceeds 900 km/h (haversine distance); return trips are de-duplicated |
| `OFF_HOURS_PRIVILEGED_LOGIN` | T1078.003 Local Accounts | Medium | Privileged account sign-in outside business hours |

All thresholds live in a single `Config` dataclass so you can tune them for your environment.

## Quick Start

Requires Python 3.9+. No dependencies.

```bash
git clone https://github.com/okrahgadiel/auth-log-threat-detector.git
cd auth-log-threat-detector
python -m detector sample_data/signins.jsonl sample_data/auth.log --json-out alerts.jsonl
```

```
Analyzed 114 events from 2 file(s); 8 alert(s)

[CRIT] SUCCESS_AFTER_BRUTE_FORCE   T1078      user=jordan@contoso.example       ip=185.220.101.47
       2026-11-10 11:00 | Successful login from an IP that was brute-forcing this account
[CRIT] MFA_FATIGUE                 T1621      user=riley@contoso.example        ip=45.137.21.9
       2026-11-11 09:00 | 5 MFA push denials in 4 min followed by an APPROVED prompt
[HIGH] IMPOSSIBLE_TRAVEL           T1078      user=jordan@contoso.example       ip=185.220.101.47
       2026-11-10 09:44 | Houston, US -> Bucharest, RO: 9,856 km in 84 min (6,998 km/h)
[HIGH] PASSWORD_SPRAY              T1110.003  user=avery@contoso.example,cas... ip=102.89.34.12
       2026-11-10 13:00 | 6 distinct accounts targeted from one IP in 10 min
[HIGH] BRUTE_FORCE                 T1110.001  user=root                         ip=203.0.113.66
       2026-11-10 22:14 | 8+ failed logins within 1 min
...
Summary: critical=2, high=5, medium=1, low=0
```

## How It Works

```
 signins.jsonl (Entra ID) ─┐
                           ├─▶ events.py: parse + normalize ─▶ Event(timestamp, user, ip, action, geo)
 auth.log (OpenSSH)  ──────┘                                      │ sorted by time
                                                                   ▼
                                    rules.py: sliding-window detectors (deque per key)
                                                                   │
                                                                   ▼
                                    Alert(rule, severity, ATT&CK technique, detail)
                                       ├─▶ console triage view
                                       └─▶ alerts.jsonl (SIEM / SOAR)
```

- **Sliding windows** use a `deque` per grouping key (user+IP, IP, or user), so detection runs in a single O(n) pass over time-sorted events.
- **Each rule fires once per key** to avoid alert floods; correlated rules such as `SUCCESS_AFTER_BRUTE_FORCE` build on the output of simpler ones.

## Sample Data

`tools/make_sample.py` deterministically generates synthetic logs: benign business-hours traffic, occasional typos, and six injected attack scenarios. The tests confirm every scenario is detected with no false positives on benign traffic.

```bash
python tools/make_sample.py
python -m unittest discover -s tests -t . -v
```

## Roadmap

- Pull sign-in logs live from Microsoft Graph (`/auditLogs/signIns`)
- Export detections as Microsoft Sentinel KQL / Sigma rules
- Enrich IPs with threat intel (Tor exit nodes, ASN reputation)

## License

MIT
