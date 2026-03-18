"""
ClawPot 核心監控引擎

整合偵測器、日誌系統與蜜罐，提供統一的監控介面。
"""

import signal
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable, List

from .detector import Detector
from .honeypot import HoneypotManager
from .logger import ClawPotLogger, Event
from .rules.openclaw_rules import Severity, RuleCategory


class MonitorConfig:
    """監控設定"""

    def __init__(
        self,
        target_pid: Optional[int] = None,
        target_process: Optional[str] = None,
        verbose: bool = False,
        log_dir: Optional[Path] = None,
        poll_interval: float = 1.0,
        alert_on_severity: Severity = Severity.MEDIUM,
    ):
        self.target_pid = target_pid
        self.target_process = target_process or "openclaw"
        self.verbose = verbose
        self.log_dir = log_dir
        self.poll_interval = poll_interval
        self.alert_on_severity = alert_on_severity


class ClawPotMonitor:
    """
    ClawPot 主監控引擎

    協調所有子系統，提供完整的 OpenClaw 行為監控。
    """

    # 嚴重程度排序
    _SEVERITY_ORDER = {
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 3,
    }

    def __init__(self, config: Optional[MonitorConfig] = None):
        self.config = config or MonitorConfig()
        self.logger = ClawPotLogger(
            log_dir=self.config.log_dir,
            verbose=self.config.verbose,
        )
        self.detector = Detector(logger=self.logger)
        self.honeypot = HoneypotManager(logger=self.logger)
        self._running = False
        self._alert_callbacks: List[Callable[[Event], None]] = []
        self._start_time: Optional[datetime] = None

    def add_alert_callback(self, callback: Callable[[Event], None]):
        """
        新增警報回呼函式

        當偵測到事件時，所有回呼都會被呼叫。
        """
        self._alert_callbacks.append(callback)

    def start(self, deploy_honeypots: bool = True):
        """
        啟動監控

        Args:
            deploy_honeypots: 是否自動部署蜜罐誘餌
        """
        self._running = True
        self._start_time = datetime.now()

        print("=" * 60)
        print("  ClawPot 監控系統啟動")
        print("=" * 60)
        print(f"  監控目標: {self.config.target_process}")
        if self.config.target_pid:
            print(f"  目標 PID: {self.config.target_pid}")
        print(f"  規則數量: {self.detector.get_active_rules_count()}")
        print(f"  啟動時間: {self._start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  日誌目錄: {self.logger.log_dir}")
        print("=" * 60)

        if deploy_honeypots:
            print("\n📌 部署蜜罐誘餌...")
            self.honeypot.deploy_all()

        # 設定 Ctrl+C 處理
        signal.signal(signal.SIGINT, self._handle_interrupt)

        print("\n🔍 監控中... 按 Ctrl+C 停止\n")

    def stop(self):
        """停止監控"""
        self._running = False
        elapsed = datetime.now() - self._start_time if self._start_time else None
        duration_str = str(elapsed).split(".")[0] if elapsed else "N/A"

        print("\n" + "=" * 60)
        print("  ClawPot 監控已停止")
        print("=" * 60)
        print(f"  監控時長: {duration_str}")
        summary = self.logger.get_summary()
        print(f"  偵測事件: {summary['total_events']} 件")
        print(f"  嚴重事件: {summary.get('critical_count', 0)} 件 (CRITICAL)")
        print(f"  高危事件: {summary.get('high_count', 0)} 件 (HIGH)")
        print(f"  蜜罐觸發: {summary.get('honeypot_triggers', 0)} 次")
        print("=" * 60)

    def report_network_event(
        self,
        host: str,
        port: int = None,
        process: str = None,
        pid: int = None,
    ) -> List[Event]:
        """
        回報一個網路連線事件供分析

        外部監控工具（如 tcpdump、Wireshark 的腳本）可呼叫此方法。
        """
        events = self.detector.check_network_connection(
            host=host,
            port=port,
            process=process or self.config.target_process,
            pid=pid or self.config.target_pid,
        )
        self._dispatch_alerts(events)
        return events

    def report_file_event(
        self,
        file_path: str,
        access_type: str = "read",
        process: str = None,
        pid: int = None,
    ) -> List[Event]:
        """
        回報一個檔案存取事件供分析

        外部監控工具（如 inotify、auditd）可呼叫此方法。
        """
        # 先檢查是否為蜜罐觸發
        is_honeypot = self.honeypot.check_trigger(file_path)
        events = self.detector.check_file_access(
            file_path=file_path,
            access_type=access_type,
            process=process or self.config.target_process,
            pid=pid or self.config.target_pid,
        )
        if is_honeypot and not events:
            # 蜜罐觸發但無規則比對時，手動記錄
            from .rules.openclaw_rules import Rule
            event = self.logger.log_event(
                rule_id="OC-FILE-002",
                rule_name="蜜罐誘餌檔案觸發",
                category=RuleCategory.HONEYPOT,
                severity=Severity.CRITICAL,
                description=f"OpenClaw 存取了蜜罐誘餌檔案: {file_path}",
                details={"file_path": file_path, "access_type": access_type},
                source_process=process or self.config.target_process,
                source_pid=pid or self.config.target_pid,
                is_honeypot_trigger=True,
            )
            events.append(event)

        self._dispatch_alerts(events)
        return events

    def report_process_event(
        self,
        activity: str,
        process: str = None,
        pid: int = None,
        details: dict = None,
    ) -> List[Event]:
        """
        回報一個進程活動事件供分析
        """
        events = self.detector.check_process_activity(
            activity=activity,
            process=process or self.config.target_process,
            pid=pid or self.config.target_pid,
            details=details,
        )
        self._dispatch_alerts(events)
        return events

    def report_raw_event(
        self,
        event_data: str,
        process: str = None,
        pid: int = None,
        details: dict = None,
    ) -> List[Event]:
        """
        回報原始事件資料供全規則比對
        """
        events = self.detector.check_raw_event(
            event_data=event_data,
            process=process or self.config.target_process,
            pid=pid or self.config.target_pid,
            details=details,
        )
        self._dispatch_alerts(events)
        return events

    def get_events(self, severity: Severity = None, honeypot_only: bool = False):
        """取得已記錄的事件"""
        return self.logger.get_events(severity=severity, honeypot_only=honeypot_only)

    def get_summary(self) -> dict:
        """取得監控摘要"""
        summary = self.logger.get_summary()
        summary["uptime"] = (
            str(datetime.now() - self._start_time).split(".")[0]
            if self._start_time
            else "N/A"
        )
        summary["target_process"] = self.config.target_process
        summary["target_pid"] = self.config.target_pid
        summary["active_rules"] = self.detector.get_active_rules_count()
        summary["honeypot_count"] = len(self.honeypot._honeypots)
        return summary

    def _dispatch_alerts(self, events: List[Event]):
        """分發警報給所有回呼"""
        for event in events:
            # 判斷是否達到警報門檻
            event_severity = Severity(event.severity)
            if (self._SEVERITY_ORDER.get(event_severity, 0) >=
                    self._SEVERITY_ORDER.get(self.config.alert_on_severity, 0)):
                self._print_alert(event)
                for callback in self._alert_callbacks:
                    try:
                        callback(event)
                    except Exception:
                        pass

    def _print_alert(self, event: Event):
        """在終端顯示警報"""
        severity_colors = {
            "low": "\033[94m",      # 藍色
            "medium": "\033[93m",   # 黃色
            "high": "\033[91m",     # 紅色
            "critical": "\033[95m", # 紫色
        }
        reset = "\033[0m"
        bold = "\033[1m"
        color = severity_colors.get(event.severity, "")

        honeypot_flag = " 🪤 [蜜罐觸發!]" if event.is_honeypot_trigger else ""
        print(f"\n{bold}{color}⚠️  警報偵測{honeypot_flag}{reset}")
        print(f"  時間: {event.timestamp}")
        print(f"  規則: [{event.rule_id}] {event.rule_name}")
        print(f"  嚴重: {color}{event.severity.upper()}{reset}")
        print(f"  類別: {event.category}")
        print(f"  說明: {event.description}")
        if event.source_process:
            print(f"  進程: {event.source_process} (PID: {event.source_pid or 'N/A'})")
        print()

    def _handle_interrupt(self, signum, frame):
        """處理 Ctrl+C 中斷"""
        print("\n\n🛑 收到停止訊號...")
        self.stop()
