"""Normalize authentication logs from different sources into one Event schema."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    user: str
    src_ip: str
    action: str  # login_success | login_failure | mfa_denied | mfa_approved
    source: str  # entra | sshd
    country: str = ""
    city: str = ""
    lat: Optional[float] = None
    lon: Optional[float] = None
    app: str = ""

    @property
    def is_failure(self) -> bool:
        return self.action == "login_failure"

    @property
    def is_success(self) -> bool:
        return self.action == "login_success"


def parse_signin_jsonl(path: Path) -> Iterator[Event]:
    """Parse Entra ID / Azure AD style sign-in logs exported as JSON Lines."""
    with open(path) as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON ({exc})") from exc
            loc = rec.get("location", {}) or {}
            yield Event(
                timestamp=datetime.fromisoformat(rec["createdDateTime"].replace("Z", "+00:00")),
                user=rec["userPrincipalName"].lower(),
                src_ip=rec.get("ipAddress", ""),
                action=_entra_action(rec),
                source="entra",
                country=loc.get("countryOrRegion", ""),
                city=loc.get("city", ""),
                lat=loc.get("latitude"),
                lon=loc.get("longitude"),
                app=rec.get("appDisplayName", ""),
            )


def _entra_action(rec: dict) -> str:
    if rec.get("mfaResult") == "denied":
        return "mfa_denied"
    if rec.get("mfaResult") == "approved":
        return "mfa_approved"
    return "login_success" if int(rec.get("status", {}).get("errorCode", 0)) == 0 else "login_failure"


_SSHD = re.compile(
    r"^(?P<ts>\S+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted) (?:password|publickey) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
)


def parse_sshd_log(path: Path) -> Iterator[Event]:
    """Parse OpenSSH auth.log lines that use ISO-8601 timestamps (rsyslog default on modern distros)."""
    with open(path) as fh:
        for line in fh:
            m = _SSHD.match(line)
            if not m:
                continue
            yield Event(
                timestamp=datetime.fromisoformat(m["ts"]),
                user=m["user"].lower(),
                src_ip=m["ip"],
                action="login_success" if m["result"] == "Accepted" else "login_failure",
                source="sshd",
                app="ssh",
            )


def load_events(paths: List[Path]) -> List[Event]:
    events: List[Event] = []
    for p in paths:
        parser = parse_signin_jsonl if p.suffix in {".jsonl", ".json"} else parse_sshd_log
        events.extend(parser(p))
    events.sort(key=lambda e: e.timestamp)
    return events
