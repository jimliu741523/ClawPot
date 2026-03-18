"""
ClawPot 日誌系統

負責記錄所有偵測到的事件與系統活動。
"""

import json
import logging
import os
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from pathlib import Path

from .rules.openclaw_rules import Severity, RuleCategory


DEFAULT_LOG_DIR = Path.home() / ".clawpot" / "logs"


@dataclass
class Event:
    """偵測事件"""
    event_id: str
    rule_id: str
    rule_name: str
    category: str
    severity: str
    description: str
    timestamp: str
    details: dict = field(default_factory=dict)
    source_process: Optional[str] = None
    source_pid: Optional[int] = None
    is_honeypot_trigger: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        severity_icons = {
            "low": "🔵",
            "medium": "🟡",
            "high": "🟠",
            "critical": "🔴",
        }
        icon = severity_icons.get(self.severity, "⚪")
        return (
            f"[{self.timestamp}] {icon} [{self.severity.upper()}] "
            f"{self.rule_id} - {self.rule_name}\n"
            f"  描述: {self.description}\n"
            f"  來源: {self.source_process or 'unknown'} (PID: {self.source_pid or 'N/A'})"
        )


class ClawPotLogger:
    """ClawPot 日誌管理器"""

    def __init__(self, log_dir: Optional[Path] = None, verbose: bool = False):
        self.log_dir = log_dir or DEFAULT_LOG_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        self._events: List[Event] = []
        self._event_counter = 0

        # 設定 Python logging
        self._setup_logging()

    def _setup_logging(self):
        log_file = self.log_dir / f"clawpot_{datetime.now().strftime('%Y%m%d')}.log"
        handlers = [logging.FileHandler(log_file, encoding="utf-8")]
        if self.verbose:
            handlers.append(logging.StreamHandler())

        logging.basicConfig(
            level=logging.DEBUG if self.verbose else logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=handlers,
        )
        self.logger = logging.getLogger("clawpot")

    def _generate_event_id(self) -> str:
        self._event_counter += 1
        ts = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"EVT-{ts}-{self._event_counter:04d}"

    def log_event(
        self,
        rule_id: str,
        rule_name: str,
        category: RuleCategory,
        severity: Severity,
        description: str,
        details: dict = None,
        source_process: str = None,
        source_pid: int = None,
        is_honeypot_trigger: bool = False,
    ) -> Event:
        """記錄一個偵測事件"""
        event = Event(
            event_id=self._generate_event_id(),
            rule_id=rule_id,
            rule_name=rule_name,
            category=category.value,
            severity=severity.value,
            description=description,
            timestamp=datetime.now().isoformat(),
            details=details or {},
            source_process=source_process,
            source_pid=source_pid,
            is_honeypot_trigger=is_honeypot_trigger,
        )

        self._events.append(event)
        self._write_event_to_file(event)

        level = {
            Severity.LOW: logging.INFO,
            Severity.MEDIUM: logging.WARNING,
            Severity.HIGH: logging.ERROR,
            Severity.CRITICAL: logging.CRITICAL,
        }.get(severity, logging.INFO)

        self.logger.log(level, f"[{rule_id}] {rule_name}: {description}")
        return event

    def _write_event_to_file(self, event: Event):
        """將事件寫入 JSON 日誌檔"""
        json_log = self.log_dir / "events.jsonl"
        with open(json_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    def get_events(
        self,
        severity: Optional[Severity] = None,
        category: Optional[RuleCategory] = None,
        honeypot_only: bool = False,
    ) -> List[Event]:
        """取得事件列表，支援篩選"""
        events = self._events
        if severity:
            events = [e for e in events if e.severity == severity.value]
        if category:
            events = [e for e in events if e.category == category.value]
        if honeypot_only:
            events = [e for e in events if e.is_honeypot_trigger]
        return events

    def get_summary(self) -> dict:
        """取得事件統計摘要"""
        total = len(self._events)
        by_severity = {}
        by_category = {}

        for event in self._events:
            by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
            by_category[event.category] = by_category.get(event.category, 0) + 1

        return {
            "total_events": total,
            "by_severity": by_severity,
            "by_category": by_category,
            "honeypot_triggers": sum(1 for e in self._events if e.is_honeypot_trigger),
            "critical_count": by_severity.get("critical", 0),
            "high_count": by_severity.get("high", 0),
        }

    def clear_events(self):
        """清除記憶體中的事件（不影響檔案）"""
        self._events.clear()
