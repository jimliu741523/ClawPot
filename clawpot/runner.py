"""
ClawPot launcher

Starts ClawPot monitoring first, then launches OpenClaw as a subprocess,
tracking its file access, network connections, and child processes throughout.
"""

import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .monitor import ClawPotMonitor, MonitorConfig
from .report.reporter import Reporter
from .rules.openclaw_rules import Severity
from .watcher import ProcessWatcher


class ClawPotRunner:
    """
    ClawPot launcher

    Usage:
        runner = ClawPotRunner(command=["openclaw", "--some-arg"])
        runner.run()
    """

    def __init__(
        self,
        command: List[str],
        verbose: bool = False,
        no_honeypot: bool = False,
        alert_on_severity: Severity = Severity.MEDIUM,
        poll_interval: float = 1.0,
        report_on_exit: bool = True,
        report_format: str = "text",
    ):
        self.command = command
        self.verbose = verbose
        self.no_honeypot = no_honeypot
        self.alert_on_severity = alert_on_severity
        self.poll_interval = poll_interval
        self.report_on_exit = report_on_exit
        self.report_format = report_format

        config = MonitorConfig(
            target_process=Path(command[0]).name,
            verbose=verbose,
            alert_on_severity=alert_on_severity,
            poll_interval=poll_interval,
        )
        self.monitor = ClawPotMonitor(config=config)
        self._proc: Optional[subprocess.Popen] = None
        self._watcher: Optional[ProcessWatcher] = None

    def run(self) -> int:
        """
        Execute the full workflow:
        1. Deploy honeypots
        2. Start ClawPot monitoring
        3. Launch the target program (OpenClaw)
        4. Monitor until the target exits
        5. Print the final report

        Returns the exit code of the target program.
        """
        # Steps 1 & 2: start monitoring
        self.monitor.start(deploy_honeypots=not self.no_honeypot)

        # Step 3: launch target
        exit_code = self._launch_and_watch()

        # Step 5: print report
        if self.report_on_exit:
            self._print_final_report()

        return exit_code

    def _launch_and_watch(self) -> int:
        """Launch the target process and start watching it"""
        proc_name = Path(self.command[0]).name
        print(f"\n[*] Launching: {' '.join(self.command)}\n")
        print("-" * 60)

        try:
            # Only pass stdin when running in a real tty (avoids errors in tests/CI)
            try:
                stdin_fd = sys.stdin.fileno()
                stdin_arg = sys.stdin
            except Exception:
                stdin_arg = subprocess.DEVNULL

            self._proc = subprocess.Popen(
                self.command,
                stdout=sys.stdout,
                stderr=sys.stderr,
                stdin=stdin_arg,
            )
        except FileNotFoundError:
            print(f"\n[!] Program not found: {self.command[0]}")
            print("    Please verify the path is correct and the program is installed.")
            self.monitor.stop()
            return 127
        except PermissionError:
            print(f"\n[!] Permission denied: {self.command[0]}")
            self.monitor.stop()
            return 126

        pid = self._proc.pid
        self.monitor.config.target_pid = pid
        self.monitor.config.target_process = proc_name

        print(f"\n[*] Target PID: {pid}  Process: {proc_name}")
        print("[*] ClawPot is watching...\n")

        # Step 4: start the process watcher
        self._watcher = ProcessWatcher(
            pid=pid,
            poll_interval=self.poll_interval,
            on_file_access=self._on_file_access,
            on_network_connect=self._on_network_connect,
            on_child_spawn=self._on_child_spawn,
        )
        self._watcher.start()

        # Wait for the target to finish
        try:
            exit_code = self._proc.wait()
        except KeyboardInterrupt:
            print("\n\n[!] User interrupted — terminating target process...")
            self._proc.terminate()
            try:
                exit_code = self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                exit_code = -1

        self._watcher.stop()
        self.monitor.stop()

        print(f"\n{'─' * 60}")
        print(f"  Target exited with code: {exit_code}")
        return exit_code

    def _on_file_access(self, file_path: str):
        """Called when the target process opens a new file"""
        events = self.monitor.report_file_event(
            file_path=file_path,
            access_type="read",
        )
        if events and self.verbose:
            for e in events:
                print(f"  [file] {file_path}")

    def _on_network_connect(self, remote_ip: str, remote_port: int):
        """Called when the target process establishes a new network connection"""
        events = self.monitor.report_network_event(
            host=remote_ip,
            port=remote_port,
        )
        if self.verbose and not events:
            # Show all connections in verbose mode even if no rule matched
            print(f"  [net] {remote_ip}:{remote_port}")

    def _on_child_spawn(self, child_pid: int, child_name: str):
        """Called when the target process spawns a child process"""
        events = self.monitor.report_process_event(
            activity=child_name,
            details={"child_pid": child_pid, "child_name": child_name},
        )
        if self.verbose:
            flag = " [!]" if events else ""
            print(f"  [child] {child_name} (PID {child_pid}){flag}")

    def _print_final_report(self):
        """Print the final behavior report after the target exits"""
        summary = self.monitor.get_summary()
        if summary["total_events"] == 0:
            print("\n[OK] No violations detected during monitoring.")
            return

        reporter = Reporter(self.monitor.logger)
        if self.report_format == "json":
            import json
            report = reporter.generate_json_report()
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(reporter.generate_text_report())
