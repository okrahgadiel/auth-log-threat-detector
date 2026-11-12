"""Detection rules mapped to MITRE ATT&CK. Each rule takes sorted events and returns Alerts."""
from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Deque, Dict, List, Set

from .events import Event


@dataclass
class Config:
    brute_force_threshold: int = 8          # failures for one user from one IP
    brute_force_window: timedelta = timedelta(minutes=10)
    spray_user_threshold: int = 6           # distinct users failed from one IP
    spray_window: timedelta = timedelta(minutes=30)
    mfa_fatigue_threshold: int = 5          # MFA denials for one user
    mfa_fatigue_window: timedelta = timedelta(minutes=15)
    max_travel_kmh: float = 900.0           # faster than a commercial jet = impossible
    business_hours: range = range(7, 19)    # 07:00-18:59 UTC
    privileged_users: Set[str] = field(default_factory=lambda: {"admin", "root"})


@dataclass
class Alert:
    rule: str
    severity: str
    technique: str
    user: str
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    detail: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d


def _sliding(events: List[Event], key, window: timedelta, threshold: int, distinct=None):
    """Yield (key, window_events) the first time a key crosses `threshold` inside `window`.
    If `distinct` is given, the threshold counts distinct values of distinct(event)."""
    buckets: Dict[tuple, Deque[Event]] = defaultdict(deque)
    fired: Set[tuple] = set()
    for ev in events:
        k = key(ev)
        if k is None:
            continue
        q = buckets[k]
        q.append(ev)
        while q and ev.timestamp - q[0].timestamp > window:
            q.popleft()
        count = len({distinct(e) for e in q}) if distinct else len(q)
        if count >= threshold and k not in fired:
            fired.add(k)
            yield k, list(q)


def brute_force(events: List[Event], cfg: Config) -> List[Alert]:
    out = []
    key = lambda e: (e.user, e.src_ip) if e.is_failure else None
    for (user, ip), hits in _sliding(events, key, cfg.brute_force_window, cfg.brute_force_threshold):
        out.append(Alert("BRUTE_FORCE", "high", "T1110.001", user, ip, hits[0].timestamp, hits[-1].timestamp,
                         f"{len(hits)}+ failed logins within {_mins(hits)} min"))
    return out


def password_spray(events: List[Event], cfg: Config) -> List[Alert]:
    out = []
    key = lambda e: e.src_ip if e.is_failure else None
    for ip, hits in _sliding(events, key, cfg.spray_window, cfg.spray_user_threshold, distinct=lambda e: e.user):
        users = sorted({e.user for e in hits})
        out.append(Alert("PASSWORD_SPRAY", "high", "T1110.003", ",".join(users[:5]) + ("..." if len(users) > 5 else ""),
                         ip, hits[0].timestamp, hits[-1].timestamp,
                         f"{len(users)} distinct accounts targeted from one IP in {_mins(hits)} min"))
    return out


def success_after_failures(events: List[Event], cfg: Config) -> List[Alert]:
    """A brute-forced (user, ip) pair that then logs in successfully = likely compromise."""
    flagged = {(a.user, a.src_ip): a for a in brute_force(events, cfg)}
    out, done = [], set()
    for ev in events:
        k = (ev.user, ev.src_ip)
        if ev.is_success and k in flagged and k not in done and ev.timestamp >= flagged[k].first_seen:
            done.add(k)
            out.append(Alert("SUCCESS_AFTER_BRUTE_FORCE", "critical", "T1078", ev.user, ev.src_ip,
                             flagged[k].first_seen, ev.timestamp,
                             "Successful login from an IP that was brute-forcing this account"))
    return out


def mfa_fatigue(events: List[Event], cfg: Config) -> List[Alert]:
    out = []
    key = lambda e: e.user if e.action == "mfa_denied" else None
    for user, hits in _sliding(events, key, cfg.mfa_fatigue_window, cfg.mfa_fatigue_threshold):
        approved = next((e for e in events if e.user == user and e.action == "mfa_approved"
                         and timedelta(0) <= e.timestamp - hits[-1].timestamp <= cfg.mfa_fatigue_window), None)
        sev = "critical" if approved else "high"
        tail = " followed by an APPROVED prompt" if approved else ""
        out.append(Alert("MFA_FATIGUE", sev, "T1621", user, hits[-1].src_ip, hits[0].timestamp,
                         (approved or hits[-1]).timestamp, f"{len(hits)} MFA push denials in {_mins(hits)} min{tail}"))
    return out


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def impossible_travel(events: List[Event], cfg: Config) -> List[Alert]:
    out = []
    last: Dict[str, Event] = {}
    seen: Set[tuple] = set()  # one alert per user per unordered location pair (suppresses the return trip)
    for ev in events:
        if not ev.is_success or ev.lat is None or ev.lon is None:
            continue
        prev = last.get(ev.user)
        last[ev.user] = ev
        if prev is None or prev.country == ev.country and prev.city == ev.city:
            continue
        km = haversine_km(prev.lat, prev.lon, ev.lat, ev.lon)
        hours = max((ev.timestamp - prev.timestamp).total_seconds() / 3600, 1 / 60)
        speed = km / hours
        pair = (ev.user, frozenset({(prev.city, prev.country), (ev.city, ev.country)}))
        if speed > cfg.max_travel_kmh and pair not in seen:
            seen.add(pair)
            out.append(Alert("IMPOSSIBLE_TRAVEL", "high", "T1078", ev.user, ev.src_ip, prev.timestamp, ev.timestamp,
                             f"{prev.city}, {prev.country} -> {ev.city}, {ev.country}: {km:,.0f} km in "
                             f"{hours * 60:.0f} min ({speed:,.0f} km/h)"))
    return out


def off_hours_privileged(events: List[Event], cfg: Config) -> List[Alert]:
    out = []
    for ev in events:
        if ev.is_success and ev.user.split("@")[0] in cfg.privileged_users and ev.timestamp.hour not in cfg.business_hours:
            out.append(Alert("OFF_HOURS_PRIVILEGED_LOGIN", "medium", "T1078.003", ev.user, ev.src_ip,
                             ev.timestamp, ev.timestamp, f"Privileged login at {ev.timestamp:%H:%M} UTC via {ev.app}"))
    return out


ALL_RULES = [success_after_failures, mfa_fatigue, brute_force, password_spray, impossible_travel, off_hours_privileged]
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def detect(events: List[Event], cfg: Config = None) -> List[Alert]:
    cfg = cfg or Config()
    alerts = [a for rule in ALL_RULES for a in rule(events, cfg)]
    alerts.sort(key=lambda a: (SEVERITY_ORDER.index(a.severity), a.first_seen))
    return alerts


def _mins(hits: List[Event]) -> int:
    return max(1, round((hits[-1].timestamp - hits[0].timestamp).total_seconds() / 60))
