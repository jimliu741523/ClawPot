"""
ClawPot 啟動器

先啟動 ClawPot 監控，再以子進程方式啟動 OpenClaw，
全程追蹤 OpenClaw 的檔案存取、網路連線與子進程。
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
    ClawPot 啟動器

    使用方式:
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
        執行完整流程:
        1. 部署蜜罐
        2. 啟動 ClawPot 監控
        3. 啟動目標程式（OpenClaw）
        4. 持續監控直到目標程式結束
        5. 輸出報告

        回傳目標程式的 exit code。
        """
        # 步驟 1 & 2: 啟動監控
        self.monitor.start(deploy_honeypots=not self.no_honeypot)

        # 步驟 3: 啟動目標程式
        exit_code = self._launch_and_watch()

        # 步驟 5: 輸出報告
        if self.report_on_exit:
            self._print_final_report()

        return exit_code

    def _launch_and_watch(self) -> int:
        """啟動目標進程並監控"""
        proc_name = Path(self.command[0]).name
        print(f"\n🚀 啟動目標程式: {' '.join(self.command)}\n")
        print("-" * 60)

        try:
            # stdin 只在真實 tty 時才傳入，避免在測試或非互動環境報錯
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
            print(f"\n❌ 找不到程式: {self.command[0]}")
            print("   請確認程式路徑正確，或已安裝於 PATH 中。")
            self.monitor.stop()
            return 127
        except PermissionError:
            print(f"\n❌ 無執行權限: {self.command[0]}")
            self.monitor.stop()
            return 126

        pid = self._proc.pid
        # 更新監控設定中的目標 PID
        self.monitor.config.target_pid = pid
        self.monitor.config.target_process = proc_name

        print(f"\n📌 目標 PID: {pid}  程式: {proc_name}")
        print("🔍 ClawPot 監控中...\n")

        # 步驟 4: 啟動進程監控器
        self._watcher = ProcessWatcher(
            pid=pid,
            poll_interval=self.poll_interval,
            on_file_access=self._on_file_access,
            on_network_connect=self._on_network_connect,
            on_child_spawn=self._on_child_spawn,
        )
        self._watcher.start()

        # 等待目標程式結束
        try:
            exit_code = self._proc.wait()
        except KeyboardInterrupt:
            print("\n\n🛑 使用者中止，正在結束目標程式...")
            self._proc.terminate()
            try:
                exit_code = self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                exit_code = -1

        # 停止監控器
        self._watcher.stop()
        self.monitor.stop()

        print(f"\n{'─' * 60}")
        print(f"  目標程式已結束，exit code: {exit_code}")
        return exit_code

    def _on_file_access(self, file_path: str):
        """目標進程開啟了新檔案"""
        events = self.monitor.report_file_event(
            file_path=file_path,
            access_type="read",
        )
        if events and self.verbose:
            for e in events:
                print(f"  [檔案] {file_path}")

    def _on_network_connect(self, remote_ip: str, remote_port: int):
        """目標進程建立了新網路連線"""
        events = self.monitor.report_network_event(
            host=remote_ip,
            port=remote_port,
        )
        if self.verbose and not events:
            # 即使無違規，verbose 模式也顯示所有連線
            print(f"  [網路] {remote_ip}:{remote_port}")

    def _on_child_spawn(self, child_pid: int, child_name: str):
        """目標進程產生了子進程"""
        events = self.monitor.report_process_event(
            activity=child_name,
            details={"child_pid": child_pid, "child_name": child_name},
        )
        if self.verbose:
            flag = " ⚠️" if events else ""
            print(f"  [子進程] {child_name} (PID {child_pid}){flag}")

    def _print_final_report(self):
        """在程式結束後印出最終報告"""
        summary = self.monitor.get_summary()
        if summary["total_events"] == 0:
            print("\n✅ 監控期間未偵測到任何違規行為。")
            return

        reporter = Reporter(self.monitor.logger)
        if self.report_format == "json":
            import json
            report = reporter.generate_json_report()
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(reporter.generate_text_report())
