"""
Honeypot module unit tests
"""

import pytest
from pathlib import Path

from clawpot.honeypot import HoneypotManager
from clawpot.logger import ClawPotLogger


@pytest.fixture
def tmp_dirs(tmp_path):
    return tmp_path / "logs", tmp_path / "honeypots"


@pytest.fixture
def logger(tmp_dirs):
    log_dir, _ = tmp_dirs
    return ClawPotLogger(log_dir=log_dir)


@pytest.fixture
def honeypot_manager(logger, tmp_dirs):
    _, hp_dir = tmp_dirs
    return HoneypotManager(logger=logger, honeypot_dir=hp_dir)


class TestHoneypotManager:

    def test_deploy_single_bait(self, honeypot_manager):
        hp = honeypot_manager.deploy("credentials")
        assert hp is not None
        assert hp.path.exists()
        assert hp.bait_type == "credentials"
        assert "clawpot" in hp.path.name

    def test_deploy_all_baits(self, honeypot_manager):
        deployed = honeypot_manager.deploy_all()
        assert len(deployed) == len(HoneypotManager.BAIT_TEMPLATES)
        for hp in deployed:
            assert hp.path.exists()

    def test_honeypot_file_contains_marker(self, honeypot_manager):
        hp = honeypot_manager.deploy("credentials")
        content = hp.path.read_text(encoding="utf-8")
        assert "HONEYPOT" in content or "clawpot" in content.lower()

    def test_trigger_detection(self, honeypot_manager):
        hp = honeypot_manager.deploy("wallet")
        triggered = honeypot_manager.check_trigger(str(hp.path))
        assert triggered is True
        assert hp.triggered is True
        assert hp.trigger_count == 1

    def test_no_trigger_for_normal_file(self, honeypot_manager):
        triggered = honeypot_manager.check_trigger("/home/user/documents/report.pdf")
        assert triggered is False

    def test_trigger_count_increments(self, honeypot_manager):
        hp = honeypot_manager.deploy("session")
        honeypot_manager.check_trigger(str(hp.path))
        honeypot_manager.check_trigger(str(hp.path))
        honeypot_manager.check_trigger(str(hp.path))
        assert hp.trigger_count == 3

    def test_get_status(self, honeypot_manager):
        honeypot_manager.deploy("credentials")
        status = honeypot_manager.get_status()
        assert len(status) == 1
        assert status[0]["bait_type"] == "credentials"
        assert "path" in status[0]
        assert "triggered" in status[0]

    def test_get_triggered_honeypots(self, honeypot_manager):
        hp1 = honeypot_manager.deploy("credentials")
        hp2 = honeypot_manager.deploy("wallet")
        honeypot_manager.check_trigger(str(hp1.path))
        triggered = honeypot_manager.get_triggered_honeypots()
        assert len(triggered) == 1
        assert triggered[0].bait_type == "credentials"

    def test_remove_all(self, honeypot_manager):
        honeypot_manager.deploy_all()
        assert len(honeypot_manager._honeypots) > 0
        honeypot_manager.remove_all()
        assert len(honeypot_manager._honeypots) == 0

    def test_state_persistence(self, logger, tmp_dirs):
        _, hp_dir = tmp_dirs
        manager1 = HoneypotManager(logger=logger, honeypot_dir=hp_dir)
        hp = manager1.deploy("personal_data")
        manager1.check_trigger(str(hp.path))

        manager2 = HoneypotManager(logger=logger, honeypot_dir=hp_dir)
        loaded_status = manager2.get_status()
        assert len(loaded_status) == 1
        assert loaded_status[0]["triggered"] is True
        assert loaded_status[0]["trigger_count"] == 1
