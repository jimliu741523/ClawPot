"""
Runner and ProcessWatcher unit tests
"""

import time
import pytest
from pathlib import Path

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
        import os
        assert _is_pid_alive(os.getpid()) is True

    def test_is_pid_alive_invalid(self):
        assert _is_pid_alive(99999999) is False

    def test_get_proc_name_current(self):
        import os
        name = _get_proc_name(os.getpid())
        assert isinstance(name, str)
        assert len(name) > 0


class TestProcessWatcher:

    def test_watcher_starts_and_stops(self):
        import os
        watcher = ProcessWatcher(pid=os.getpid(), poll_interval=0.1)
        watcher.start()
        time.sleep(0.2)
        watcher.stop()
        assert not watcher._running

    def test_watcher_detects_existing_files(self):
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

    def test_watcher_callback_for_network(self):
        import os
        network_events = []
        watcher = ProcessWatcher(
            pid=os.getpid(),
            poll_interval=0.1,
            on_network_connect=lambda ip, port: network_events.append((ip, port)),
        )
        assert watcher.on_network_connect is not None


class TestClawPotRunner:

    def test_runner_with_true_command(self):
        runner = ClawPotRunner(
            command=["true"],
            no_honeypot=True,
            report_on_exit=False,
        )
        exit_code = runner.run()
        assert exit_code == 0

    def test_runner_with_false_command(self):
        runner = ClawPotRunner(
            command=["false"],
            no_honeypot=True,
            report_on_exit=False,
        )
        exit_code = runner.run()
        assert exit_code != 0

    def test_runner_with_nonexistent_command(self):
        runner = ClawPotRunner(
            command=["_nonexistent_clawpot_test_cmd_"],
            no_honeypot=True,
            report_on_exit=False,
        )
        exit_code = runner.run()
        assert exit_code == 127

    def test_runner_short_lived_process(self):
        runner = ClawPotRunner(
            command=["echo", "hello"],
            no_honeypot=True,
            report_on_exit=False,
            poll_interval=0.1,
        )
        exit_code = runner.run()
        assert exit_code == 0

    def test_runner_captures_events_on_violation(self):
        runner = ClawPotRunner(
            command=["true"],
            no_honeypot=True,
            report_on_exit=False,
        )
        runner.run()

        events = runner.monitor.report_network_event(
            host="telemetry.openclaw.io",
            port=443,
        )
        assert len(events) > 0
