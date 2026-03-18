"""
ClawPot 報告產生器

將偵測事件轉換為易讀的分析報告。
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..logger import ClawPotLogger, Event
from ..rules.openclaw_rules import Severity, RuleCategory


class Reporter:
    """
    行為分析報告產生器

    將 ClawPot 偵測到的事件整理成人類可讀的報告。
    """

    def __init__(self, logger: ClawPotLogger):
        self.logger = logger

    def generate_text_report(self, output_path: Optional[Path] = None) -> str:
        """
        產生文字格式報告

        Args:
            output_path: 若指定，報告會同時寫入此路徑

        Returns:
            報告內容字串
        """
        events = self.logger.get_events()
        summary = self.logger.get_summary()
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            "=" * 70,
            "  ClawPot 非法行為偵測報告",
            f"  產生時間: {generated_at}",
            "=" * 70,
            "",
            "【摘要】",
            f"  總事件數:     {summary['total_events']}",
            f"  嚴重 (CRITICAL): {summary.get('by_severity', {}).get('critical', 0)} 件",
            f"  高危 (HIGH):     {summary.get('by_severity', {}).get('high', 0)} 件",
            f"  中危 (MEDIUM):   {summary.get('by_severity', {}).get('medium', 0)} 件",
            f"  低危 (LOW):      {summary.get('by_severity', {}).get('low', 0)} 件",
            f"  蜜罐觸發:     {summary.get('honeypot_triggers', 0)} 次",
            "",
            "【事件分類統計】",
        ]

        by_category = summary.get("by_category", {})
        category_names = {
            "network": "網路活動",
            "file_access": "檔案存取",
            "privacy": "隱私侵犯",
            "resource_abuse": "資源濫用",
            "tracking": "行為追蹤",
            "process": "進程活動",
            "honeypot": "蜜罐觸發",
        }
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
            name = category_names.get(cat, cat)
            lines.append(f"  {name}: {count} 件")

        # 蜜罐觸發事件（最優先）
        honeypot_events = [e for e in events if e.is_honeypot_trigger]
        if honeypot_events:
            lines += [
                "",
                "【🪤 蜜罐觸發事件 (確認非法行為)】",
                "-" * 50,
            ]
            for event in honeypot_events:
                lines += self._format_event(event)

        # 嚴重事件
        critical_events = [e for e in events if e.severity == "critical" and not e.is_honeypot_trigger]
        if critical_events:
            lines += [
                "",
                "【🔴 嚴重事件 (CRITICAL)】",
                "-" * 50,
            ]
            for event in critical_events:
                lines += self._format_event(event)

        # 高危事件
        high_events = [e for e in events if e.severity == "high"]
        if high_events:
            lines += [
                "",
                "【🟠 高危事件 (HIGH)】",
                "-" * 50,
            ]
            for event in high_events:
                lines += self._format_event(event)

        # 其他事件
        other_events = [e for e in events if e.severity in ("medium", "low")]
        if other_events:
            lines += [
                "",
                "【其他事件 (MEDIUM/LOW)】",
                "-" * 50,
            ]
            for event in other_events:
                lines += self._format_event(event)

        lines += [
            "",
            "=" * 70,
            "  報告結束 - ClawPot 蜜罐監控系統",
            "=" * 70,
        ]

        report = "\n".join(lines)

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report, encoding="utf-8")
            print(f"✅ 報告已儲存至: {output_path}")

        return report

    def generate_json_report(self, output_path: Optional[Path] = None) -> dict:
        """
        產生 JSON 格式報告

        Args:
            output_path: 若指定，報告會同時寫入此路徑

        Returns:
            報告資料字典
        """
        events = self.logger.get_events()
        summary = self.logger.get_summary()

        report_data = {
            "generated_at": datetime.now().isoformat(),
            "summary": summary,
            "events": [e.to_dict() for e in events],
            "honeypot_triggers": [e.to_dict() for e in events if e.is_honeypot_trigger],
            "critical_events": [e.to_dict() for e in events if e.severity == "critical"],
        }

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(report_data, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            print(f"✅ JSON 報告已儲存至: {output_path}")

        return report_data

    def print_events_table(self, events: Optional[List[Event]] = None):
        """以表格格式印出事件列表"""
        if events is None:
            events = self.logger.get_events()

        if not events:
            print("  (無事件記錄)")
            return

        severity_icons = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}

        print(f"\n{'時間':<22} {'嚴重':<8} {'規則ID':<12} {'規則名稱':<25} {'類別'}")
        print("-" * 90)
        for event in events:
            icon = severity_icons.get(event.severity, "⚪")
            honeypot = " 🪤" if event.is_honeypot_trigger else ""
            ts = event.timestamp[:19].replace("T", " ")
            print(
                f"{ts:<22} {icon} {event.severity:<6} {event.rule_id:<12} "
                f"{event.rule_name:<25} {event.category}{honeypot}"
            )

    def _format_event(self, event: Event) -> List[str]:
        """格式化單一事件為文字行"""
        lines = [
            f"  [{event.timestamp[:19].replace('T', ' ')}] {event.event_id}",
            f"  規則: [{event.rule_id}] {event.rule_name}",
            f"  說明: {event.description}",
        ]
        if event.source_process:
            lines.append(f"  進程: {event.source_process} (PID: {event.source_pid or 'N/A'})")
        if event.details:
            for key, val in event.details.items():
                if key not in ("matched_indicator",):
                    lines.append(f"  {key}: {val}")
        lines.append("")
        return lines
