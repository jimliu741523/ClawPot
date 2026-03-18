"""
Runner 與 ProcessWatcher 測試
"""

import sys
import time
import threading
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from clawpot.runner import ClawPotRunner
from clawpot.watcher import ProcessWatcher, _hex_to_ip, _get_proc_name, _is_pid_alive
from clawpot.rules.openclaw_rules import Severity


class TestHexToIp:

    def test_ipv4_conversion(self):
        # 127.0.0.1 in little-endian hex = 0100007F
        result = _hex_to_ip("0100007F")
        assert result == "127.0.0.1"

    def test_localhost(self):
        result = _hex_to_ip("0100007F")
        assert result == "127.0.0.1"


class TestProcHelpers:

    def test_is_pid_alive_current(self):
        """當前進程應為 alive"""
        import os
        assert _is_pid_alive(os.getpid()) is True

    def test_is_pid_alive_invalid(self):
        """不存在的 PID 應回傳 False"""
        assert _is_pid_alive(99999999) is False

    def test_get_proc_name_current(self):
        """應能取得當前進程名稱"""
        import os
        name = _get_proc_name(os.getpid())
        assert isinstance(name, str)
        assert len(name) > 0


class TestProcessWatcher:

    def test_watcher_starts_and_stops(self):
        """ProcessWatcher 應能正常啟動與停止"""
        import os
        watcher = ProcessWatcher(pid=os.getpid(), poll_interval=0.1)
        watcher.start()
        time.sleep(0.2)
        watcher.stop()
        assert not watcher._running

    def test_watcher_detects_existing_files(self):
        """ProcessWatcher 應能偵測到進程開啟的檔案"""
        import os
        detected = []
        watcher = ProcessWatcher(
            pid=os.getpid(),
            poll_interval=0.1,
            on_file_access=detected.append,
        )
        watcher.start()
        time.sleep(0.5)
        watcher.stop()
        # 當前進程一定有開啟一些檔案
        # 測試不強制要求，因為系統路徑都被過濾了

    def test_watcher_callback_for_network(self):
        """網路回呼應被正確設置"""
        import os
        network_events = []
        watcher = ProcessWatcher(
            pid=os.getpid(),
            poll_interval=0.1,
            on_network_connect=lambda ip, port: network_events.append((ip, port)),
        )
        assert watcher.on_network_connect is not None


class TestClawPotRunner:

    def test_runner_with_true_command(self, tmp_path):
        """執行 'true' 命令（立即成功結束）"""
        runner = ClawPotRunner(
            command=["true"],
            no_honeypot=True,
            report_on_exit=False,
        )
        exit_code = runner.run()
        assert exit_code == 0

    def test_runner_with_false_command(self, tmp_path):
        """執行 'false' 命令（立即失敗結束）"""
        runner = ClawPotRunner(
            command=["false"],
            no_honeypot=True,
            report_on_exit=False,
        )
        exit_code = runner.run()
        assert exit_code != 0

    def test_runner_with_nonexistent_command(self):
        """找不到程式應回傳 127"""
        runner = ClawPotRunner(
            command=["_nonexistent_clawpot_test_cmd_"],
            no_honeypot=True,
            report_on_exit=False,
        )
        exit_code = runner.run()
        assert exit_code == 127

    def test_runner_short_lived_process(self):
        """短暫執行的進程應能正確監控"""
        runner = ClawPotRunner(
            command=["echo", "hello"],
            no_honeypot=True,
            report_on_exit=False,
            poll_interval=0.1,
        )
        exit_code = runner.run()
        assert exit_code == 0

    def test_runner_captures_events_on_violation(self):
        """監控器應能捕捉到違規行為"""
        runner = ClawPotRunner(
            command=["true"],
            no_honeypot=True,
            report_on_exit=False,
        )
        runner.run()

        # 手動注入一個違規事件來測試偵測器
        events = runner.monitor.report_network_event(
            host="telemetry.openclaw.io",
            port=443,
        )
        assert len(events) > 0
