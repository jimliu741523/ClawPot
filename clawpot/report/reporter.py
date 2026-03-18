"""
ClawPot report generator

Converts detected events into human-readable analysis reports.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..logger import ClawPotLogger, Event
from ..rules.openclaw_rules import Severity, RuleCategory


class Reporter:
    """
    Behavior analysis report generator

    Formats ClawPot detected events into readable reports.
    """

    def __init__(self, logger: ClawPotLogger):
        self.logger = logger

    def generate_text_report(self, output_path: Optional[Path] = None) -> str:
        """
        Generate a plain-text report.

        Args:
            output_path: If provided, the report is also written to this path.

        Returns:
            Report content as a string.
        """
        events = self.logger.get_events()
        summary = self.logger.get_summary()
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            "=" * 70,
            "  ClawPot Illegal Behavior Detection Report",
            f"  Generated: {generated_at}",
            "=" * 70,
            "",
            "[Summary]",
            f"  Total events  : {summary['total_events']}",
            f"  Critical      : {summary.get('by_severity', {}).get('critical', 0)}",
            f"  High          : {summary.get('by_severity', {}).get('high', 0)}",
            f"  Medium        : {summary.get('by_severity', {}).get('medium', 0)}",
            f"  Low           : {summary.get('by_severity', {}).get('low', 0)}",
            f"  Honeypot hits : {summary.get('honeypot_triggers', 0)}",
            "",
            "[Events by Category]",
        ]

        by_category = summary.get("by_category", {})
        category_names = {
            "network": "Network Activity",
            "file_access": "File Access",
            "privacy": "Privacy Violation",
            "resource_abuse": "Resource Abuse",
            "tracking": "Behavior Tracking",
            "process": "Process Activity",
            "honeypot": "Honeypot Trigger",
        }
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
            name = category_names.get(cat, cat)
            lines.append(f"  {name}: {count}")

        # Honeypot events first (highest priority)
        honeypot_events = [e for e in events if e.is_honeypot_trigger]
        if honeypot_events:
            lines += [
                "",
                "[HONEYPOT TRIGGERED — Confirmed Illegal Behavior]",
                "-" * 50,
            ]
            for event in honeypot_events:
                lines += self._format_event(event)

        # Critical events
        critical_events = [e for e in events if e.severity == "critical" and not e.is_honeypot_trigger]
        if critical_events:
            lines += [
                "",
                "[CRITICAL Events]",
                "-" * 50,
            ]
            for event in critical_events:
                lines += self._format_event(event)

        # High events
        high_events = [e for e in events if e.severity == "high"]
        if high_events:
            lines += [
                "",
                "[HIGH Events]",
                "-" * 50,
            ]
            for event in high_events:
                lines += self._format_event(event)

        # Medium/Low events
        other_events = [e for e in events if e.severity in ("medium", "low")]
        if other_events:
            lines += [
                "",
                "[MEDIUM / LOW Events]",
                "-" * 50,
            ]
            for event in other_events:
                lines += self._format_event(event)

        lines += [
            "",
            "=" * 70,
            "  End of Report — ClawPot Honeypot Monitoring System",
            "=" * 70,
        ]

        report = "\n".join(lines)

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(report, encoding="utf-8")
            print(f"  Report saved to: {output_path}")

        return report

    def generate_json_report(self, output_path: Optional[Path] = None) -> dict:
        """
        Generate a JSON report.

        Args:
            output_path: If provided, the report is also written to this path.

        Returns:
            Report data as a dictionary.
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
            print(f"  JSON report saved to: {output_path}")

        return report_data

    def print_events_table(self, events: Optional[List[Event]] = None):
        """Print events in table format"""
        if events is None:
            events = self.logger.get_events()

        if not events:
            print("  (no events recorded)")
            return

        severity_icons = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}

        print(f"\n{'Timestamp':<22} {'Sev':<8} {'Rule ID':<12} {'Rule Name':<30} {'Category'}")
        print("-" * 95)
        for event in events:
            icon = severity_icons.get(event.severity, "⚪")
            honeypot = " [HP]" if event.is_honeypot_trigger else ""
            ts = event.timestamp[:19].replace("T", " ")
            print(
                f"{ts:<22} {icon} {event.severity:<6} {event.rule_id:<12} "
                f"{event.rule_name:<30} {event.category}{honeypot}"
            )

    def _format_event(self, event: Event) -> List[str]:
        """Format a single event as text lines"""
        lines = [
            f"  [{event.timestamp[:19].replace('T', ' ')}] {event.event_id}",
            f"  Rule   : [{event.rule_id}] {event.rule_name}",
            f"  Detail : {event.description}",
        ]
        if event.source_process:
            lines.append(f"  Process: {event.source_process} (PID: {event.source_pid or 'N/A'})")
        if event.details:
            for key, val in event.details.items():
                if key not in ("matched_indicator",):
                    lines.append(f"  {key}: {val}")
        lines.append("")
        return lines
