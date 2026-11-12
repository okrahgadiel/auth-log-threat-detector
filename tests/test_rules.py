import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from detector.events import Event, load_events, parse_sshd_log
from detector.rules import (
    Config,
    brute_force,
    detect,
    haversine_km,
    impossible_travel,
    mfa_fatigue,
    off_hours_privileged,
    password_spray,
    success_after_failures,
)

T0 = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
DATA = Path(__file__).resolve().parent.parent / "sample_data"


def ev(minutes, user="u@x", ip="1.1.1.1", action="login_failure", **kw):
    return Event(T0 + timedelta(minutes=minutes), user, ip, action, "entra", **kw)


class BruteForceTests(unittest.TestCase):
    def test_fires_at_threshold_within_window(self):
        events = [ev(i) for i in range(8)]
        self.assertEqual(len(brute_force(events, Config())), 1)

    def test_does_not_fire_when_spread_out(self):
        events = [ev(i * 5) for i in range(8)]  # 35 minutes, window is 10
        self.assertEqual(brute_force(events, Config()), [])

    def test_success_after_brute_force_is_critical(self):
        events = [ev(i) for i in range(8)] + [ev(9, action="login_success")]
        alerts = success_after_failures(events, Config())
        self.assertEqual([a.severity for a in alerts], ["critical"])


class SprayTests(unittest.TestCase):
    def test_many_users_one_ip(self):
        events = [ev(i, user=f"user{i}@x") for i in range(6)]
        alerts = password_spray(events, Config())
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].technique, "T1110.003")

    def test_one_user_many_failures_is_not_spray(self):
        self.assertEqual(password_spray([ev(i) for i in range(10)], Config()), [])


class MfaFatigueTests(unittest.TestCase):
    def test_denials_then_approval_escalates_to_critical(self):
        events = [ev(i, action="mfa_denied") for i in range(5)] + [ev(7, action="mfa_approved")]
        self.assertEqual(mfa_fatigue(events, Config())[0].severity, "critical")

    def test_denials_only_is_high(self):
        events = [ev(i, action="mfa_denied") for i in range(5)]
        self.assertEqual(mfa_fatigue(events, Config())[0].severity, "high")


class TravelTests(unittest.TestCase):
    def test_haversine_houston_to_dallas(self):
        self.assertAlmostEqual(haversine_km(29.76, -95.37, 32.78, -96.80), 362, delta=10)

    def test_impossible_travel_detected_once(self):
        houston = dict(city="Houston", country="US", lat=29.76, lon=-95.37)
        lagos = dict(city="Lagos", country="NG", lat=6.52, lon=3.38)
        events = [ev(0, action="login_success", **houston), ev(30, action="login_success", **lagos),
                  ev(60, action="login_success", **houston)]
        self.assertEqual(len(impossible_travel(events, Config())), 1)

    def test_realistic_travel_is_fine(self):
        houston = dict(city="Houston", country="US", lat=29.76, lon=-95.37)
        dallas = dict(city="Dallas", country="US", lat=32.78, lon=-96.80)
        events = [ev(0, action="login_success", **houston), ev(120, action="login_success", **dallas)]
        self.assertEqual(impossible_travel(events, Config()), [])


class OffHoursTests(unittest.TestCase):
    def test_admin_at_3am(self):
        e = Event(T0.replace(hour=3), "admin@x", "10.0.0.1", "login_success", "entra")
        self.assertEqual(len(off_hours_privileged([e], Config())), 1)


class ParserAndEndToEndTests(unittest.TestCase):
    def test_sshd_parser_handles_invalid_user(self):
        events = list(parse_sshd_log(DATA / "auth.log"))
        self.assertTrue(any(e.user == "oracle" for e in events))
        self.assertTrue(any(e.is_success and e.user == "deploy" for e in events))

    def test_sample_data_detects_every_scenario(self):
        alerts = detect(load_events([DATA / "signins.jsonl", DATA / "auth.log"]))
        rules = {a.rule for a in alerts}
        self.assertEqual(rules, {"SUCCESS_AFTER_BRUTE_FORCE", "MFA_FATIGUE", "IMPOSSIBLE_TRAVEL", "BRUTE_FORCE",
                                 "PASSWORD_SPRAY", "OFF_HOURS_PRIVILEGED_LOGIN"})
        self.assertEqual(alerts[0].severity, "critical")


if __name__ == "__main__":
    unittest.main()
