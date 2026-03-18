"""
ClawPot core monitoring engine

Integrates the detector, logger, and honeypot manager into a unified monitoring interface.
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
    """Monitor configuration"""

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
    ClawPot main monitoring engine

    Coordinates all subsystems to provide complete OpenClaw behavior monitoring.
    """

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
        """Register a callback to be called whenever an event is detected"""
        self._alert_callbacks.append(callback)

    def start(self, deploy_honeypots: bool = True):
        """
        Start monitoring.

        Args:
            deploy_honeypots: Whether to automatically deploy honeypot bait files
        """
        self._running = True
        self._start_time = datetime.now()

        print("=" * 60)
        print("  ClawPot Monitor Started")
        print("=" * 60)
        print(f"  Target process : {self.config.target_process}")
        if self.config.target_pid:
            print(f"  Target PID     : {self.config.target_pid}")
        print(f"  Active rules   : {self.detector.get_active_rules_count()}")
        print(f"  Started at     : {self._start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Log directory  : {self.logger.log_dir}")
        print("=" * 60)

        if deploy_honeypots:
            print("\n[*] Deploying honeypot bait files...")
            self.honeypot.deploy_all()

        signal.signal(signal.SIGINT, self._handle_interrupt)

        print("\n[*] Monitoring... Press Ctrl+C to stop\n")

    def stop(self):
        """Stop monitoring and print a summary"""
        self._running = False
        elapsed = datetime.now() - self._start_time if self._start_time else None
        duration_str = str(elapsed).split(".")[0] if elapsed else "N/A"

        print("\n" + "=" * 60)
        print("  ClawPot Monitor Stopped")
        print("=" * 60)
        print(f"  Duration         : {duration_str}")
        summary = self.logger.get_summary()
        print(f"  Total events     : {summary['total_events']}")
        print(f"  Critical events  : {summary.get('critical_count', 0)}")
        print(f"  High events      : {summary.get('high_count', 0)}")
        print(f"  Honeypot triggers: {summary.get('honeypot_triggers', 0)}")
        print("=" * 60)

    def report_network_event(
        self,
        host: str,
        port: int = None,
        process: str = None,
        pid: int = None,
    ) -> List[Event]:
        """
        Report a network connection event for analysis.

        External tools (e.g. tcpdump scripts) can call this method.
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
        Report a file access event for analysis.

        External tools (e.g. inotify, auditd) can call this method.
        """
        is_honeypot = self.honeypot.check_trigger(file_path)
        events = self.detector.check_file_access(
            file_path=file_path,
            access_type=access_type,
            process=process or self.config.target_process,
            pid=pid or self.config.target_pid,
        )
        if is_honeypot and not events:
            event = self.logger.log_event(
                rule_id="OC-FILE-002",
                rule_name="Honeypot Bait File Triggered",
                category=RuleCategory.HONEYPOT,
                severity=Severity.CRITICAL,
                description=f"OpenClaw accessed a honeypot bait file: {file_path}",
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
        """Report a process activity event for analysis"""
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
        """Report raw event data to be matched against all rules"""
        events = self.detector.check_raw_event(
            event_data=event_data,
            process=process or self.config.target_process,
            pid=pid or self.config.target_pid,
            details=details,
        )
        self._dispatch_alerts(events)
        return events

    def get_events(self, severity: Severity = None, honeypot_only: bool = False):
        """Get recorded events"""
        return self.logger.get_events(severity=severity, honeypot_only=honeypot_only)

    def get_summary(self) -> dict:
        """Get monitoring summary"""
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
        """Dispatch alerts to all registered callbacks"""
        for event in events:
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
        """Print an alert to the terminal"""
        severity_colors = {
            "low": "\033[94m",      # Blue
            "medium": "\033[93m",   # Yellow
            "high": "\033[91m",     # Red
            "critical": "\033[95m", # Magenta
        }
        reset = "\033[0m"
        bold = "\033[1m"
        color = severity_colors.get(event.severity, "")

        honeypot_flag = " [HONEYPOT TRIGGERED]" if event.is_honeypot_trigger else ""
        print(f"\n{bold}{color}[!] ALERT{honeypot_flag}{reset}")
        print(f"  Time    : {event.timestamp}")
        print(f"  Rule    : [{event.rule_id}] {event.rule_name}")
        print(f"  Severity: {color}{event.severity.upper()}{reset}")
        print(f"  Category: {event.category}")
        print(f"  Detail  : {event.description}")
        if event.source_process:
            print(f"  Process : {event.source_process} (PID: {event.source_pid or 'N/A'})")
        print()

    def _handle_interrupt(self, signum, frame):
        """Handle Ctrl+C interrupt"""
        print("\n\n[!] Stop signal received...")
        self.stop()
