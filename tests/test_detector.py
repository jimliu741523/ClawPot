"""
偵測器單元測試
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
        """偵測器應載入所有規則"""
        assert detector.get_active_rules_count() > 0

    def test_rules_summary(self, detector):
        """規則摘要應包含各分類"""
        summary = detector.get_rules_summary()
        assert "total" in summary
        assert summary["total"] > 0
        assert "by_severity" in summary
        assert "by_category" in summary

    def test_detect_malicious_network_connection(self, detector):
        """應偵測到 OpenClaw 的惡意網路連線"""
        events = detector.check_network_connection(
            host="telemetry.openclaw.io",
            port=443,
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0
        assert any(e.category == "network" for e in events)

    def test_clean_network_connection(self, detector):
        """正常連線不應觸發警報"""
        events = detector.check_network_connection(
            host="www.google.com",
            port=443,
            process="browser",
            pid=1234,
        )
        assert len(events) == 0

    def test_detect_cookie_access(self, detector):
        """應偵測到 Cookie 存取行為"""
        events = detector.check_file_access(
            file_path="/home/user/.mozilla/firefox/profile/cookies.sqlite",
            access_type="read",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0
        assert any(e.severity in ("high", "critical") for e in events)

    def test_detect_honeypot_file_access(self, detector):
        """應偵測到蜜罐檔案存取"""
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
        """應偵測到鍵盤記錄行為"""
        events = detector.check_process_activity(
            activity="SetWindowsHookEx keyboard_hook installed",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0
        assert any(e.severity == "critical" for e in events)

    def test_detect_password_file_access(self, detector):
        """應偵測到密碼庫存取"""
        events = detector.check_file_access(
            file_path="C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            access_type="read",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0

    def test_detect_suspicious_subprocess(self, detector):
        """應偵測到可疑子進程"""
        events = detector.check_process_activity(
            activity="/bin/bash -c 'curl http://evil.com'",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0

    def test_raw_event_detection(self, detector):
        """應能對原始事件資料進行偵測"""
        events = detector.check_raw_event(
            event_data="Process openclaw connected to analytics.openclaw.io:443",
            process="openclaw",
            pid=9999,
        )
        assert len(events) > 0

    def test_wildcard_indicator_matching(self, detector):
        """萬用字元規則應正確比對"""
        # 測試 *.openclaw.io 規則
        events = detector.check_network_connection(
            host="secret.data.openclaw.io",
            port=443,
        )
        assert len(events) > 0

    def test_indicator_case_insensitive(self, detector):
        """指標比對應不區分大小寫"""
        events = detector.check_file_access(
            file_path="/PATH/TO/COOKIES.SQLITE",
            access_type="read",
            process="openclaw",
        )
        assert len(events) > 0


class TestLogger:

    def test_log_event(self, logger):
        """應能記錄事件"""
        event = logger.log_event(
            rule_id="TEST-001",
            rule_name="測試規則",
            category=RuleCategory.NETWORK,
            severity=Severity.HIGH,
            description="這是一個測試事件",
        )
        assert event is not None
        assert event.rule_id == "TEST-001"
        assert event.severity == "high"

    def test_get_events(self, logger):
        """應能取得已記錄的事件"""
        logger.log_event(
            rule_id="TEST-001",
            rule_name="測試",
            category=RuleCategory.NETWORK,
            severity=Severity.HIGH,
            description="測試",
        )
        events = logger.get_events()
        assert len(events) == 1

    def test_filter_events_by_severity(self, logger):
        """應能依嚴重程度篩選事件"""
        logger.log_event("T-001", "Test", RuleCategory.NETWORK, Severity.LOW, "low event")
        logger.log_event("T-002", "Test", RuleCategory.NETWORK, Severity.CRITICAL, "critical event")

        critical = logger.get_events(severity=Severity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].severity == "critical"

    def test_get_summary(self, logger):
        """摘要應包含正確統計"""
        logger.log_event("T-001", "Test", RuleCategory.NETWORK, Severity.HIGH, "test")
        logger.log_event("T-002", "Test", RuleCategory.PRIVACY, Severity.CRITICAL, "test")

        summary = logger.get_summary()
        assert summary["total_events"] == 2
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["critical"] == 1

    def test_event_written_to_file(self, logger, tmp_log_dir):
        """事件應寫入 JSONL 檔案"""
        logger.log_event("T-001", "Test", RuleCategory.NETWORK, Severity.HIGH, "test")

        json_log = tmp_log_dir / "events.jsonl"
        assert json_log.exists()
        content = json_log.read_text(encoding="utf-8")
        assert "T-001" in content
