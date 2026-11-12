"""Generate deterministic synthetic sign-in logs containing benign noise plus attack scenarios.

python tools/make_sample.py   ->  sample_data/signins.jsonl, sample_data/auth.log
"""
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
OUT = Path(__file__).resolve().parent.parent / "sample_data"
START = datetime(2026, 11, 10, 8, 0, 0)

CITIES = {
    "Houston": ("US", 29.76, -95.37), "Katy": ("US", 29.79, -95.82), "Dallas": ("US", 32.78, -96.80),
    "Lagos": ("NG", 6.52, 3.38), "Bucharest": ("RO", 44.43, 26.10),
}
USERS = [f"{n}@contoso.example" for n in
         ["avery", "jordan", "riley", "casey", "taylor", "jamie", "drew", "quinn", "morgan", "sam", "admin"]]
HOME = {u: random.choice(["Houston", "Katy", "Dallas"]) for u in USERS}
HOME_IP = {u: f"10.20.{i}.{random.randint(10, 250)}" for i, u in enumerate(USERS)}


def rec(ts, user, city, ip, ok=True, mfa=None, app="Microsoft 365"):
    country, lat, lon = CITIES[city]
    r = {"createdDateTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "userPrincipalName": user, "ipAddress": ip,
         "appDisplayName": app, "status": {"errorCode": 0 if ok else 50126},
         "location": {"city": city, "countryOrRegion": country, "latitude": lat, "longitude": lon}}
    if mfa:
        r["mfaResult"] = mfa
    return r


records = []
# Benign: each user logs in a few times during business hours, occasional typo
for user in USERS[:-1]:
    for day in range(2):
        for _ in range(random.randint(2, 4)):
            ts = START + timedelta(days=day, minutes=random.randint(0, 9 * 60))
            if random.random() < 0.15:
                records.append(rec(ts, user, HOME[user], HOME_IP[user], ok=False))
                ts += timedelta(seconds=30)
            records.append(rec(ts, user, HOME[user], HOME_IP[user]))

# 1) Brute force against jordan, then success (account takeover)
t = START + timedelta(hours=3)
for i in range(12):
    records.append(rec(t + timedelta(seconds=40 * i), "jordan@contoso.example", "Bucharest", "185.220.101.47", ok=False))
records.append(rec(t + timedelta(minutes=9), "jordan@contoso.example", "Bucharest", "185.220.101.47"))

# 2) Password spray: one IP, one attempt each against many users
t = START + timedelta(hours=5)
for i, user in enumerate(USERS):
    records.append(rec(t + timedelta(minutes=2 * i), user, "Lagos", "102.89.34.12", ok=False))

# 3) MFA fatigue against riley ending in an approval
t = START + timedelta(days=1, hours=1)
for i in range(7):
    records.append(rec(t + timedelta(minutes=i), "riley@contoso.example", "Bucharest", "45.137.21.9", mfa="denied"))
records.append(rec(t + timedelta(minutes=9), "riley@contoso.example", "Bucharest", "45.137.21.9", mfa="approved"))

# 4) Impossible travel: casey at home in Texas, then Lagos 40 minutes later
t = START + timedelta(days=1, hours=4)
records.append(rec(t, "casey@contoso.example", HOME["casey@contoso.example"], HOME_IP["casey@contoso.example"]))
records.append(rec(t + timedelta(minutes=40), "casey@contoso.example", "Lagos", "102.89.40.7"))

# 5) Off-hours admin login
records.append(rec(datetime(2026, 11, 11, 2, 47, 0), "admin@contoso.example", "Houston", "10.20.10.5", app="Azure Portal"))

records.sort(key=lambda r: r["createdDateTime"])
with open(OUT / "signins.jsonl", "w") as fh:
    for r in records:
        fh.write(json.dumps(r) + "\n")

# Linux sshd log: SSH brute force against root from a scanner, plus normal deploy logins
lines = []
t = datetime(2026, 11, 10, 22, 14, 0)
for i in range(15):
    user = "root" if i % 3 else "invalid user oracle"
    lines.append(f"{(t + timedelta(seconds=6 * i)).isoformat()}+00:00 web01 sshd[{4100 + i}]: "
                 f"Failed password for {user} from 203.0.113.66 port {50000 + i} ssh2")
for h in (9, 13, 16):
    lines.append(f"2026-11-10T{h:02d}:05:00+00:00 web01 sshd[{3000 + h}]: "
                 f"Accepted publickey for deploy from 10.20.3.15 port 52222 ssh2")
lines.sort()
(OUT / "auth.log").write_text("\n".join(lines) + "\n")
print(f"wrote {len(records)} sign-in records and {len(lines)} sshd lines")
