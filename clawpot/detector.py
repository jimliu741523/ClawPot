"""
ClawPot behavior detector

Analyzes OpenClaw's behavior against the rule set to identify illegal activity.
"""

import re
from typing import List, Optional, Tuple

from .rules.openclaw_rules import OPENCLAW_RULES, Rule, Severity, RuleCategory
from .logger import ClawPotLogger, Event


class DetectionResult:
    """Result of a rule match attempt"""

    def __init__(self, matched: bool, rule: Optional[Rule] = None, matched_indicator: str = ""):
        self.matched = matched
        self.rule = rule
        self.matched_indicator = matched_indicator

    def __bool__(self):
        return self.matched


class Detector:
    """
    OpenClaw illegal behavior detector

    Compares observed behavior against the rule library to identify illegal activity.
    """

    def __init__(self, logger: ClawPotLogger, custom_rules: List[Rule] = None):
        self.logger = logger
        self.rules = list(OPENCLAW_RULES)
        if custom_rules:
            self.rules.extend(custom_rules)
        # Only keep enabled rules
        self.rules = [r for r in self.rules if r.enabled]

    def check_network_connection(
        self,
        host: str,
        port: int = None,
        process: str = None,
        pid: int = None,
    ) -> List[Event]:
        """
        Check whether a network connection violates any rule

        Args:
            host: Target hostname or IP address
            port: Target port number
            process: Name of the process initiating the connection
            pid: PID of the process initiating the connection
        """
        events = []
        network_rules = [r for r in self.rules if r.category == RuleCategory.NETWORK]

        for rule in network_rules:
            result = self._match_indicators(host, rule.indicators)
            if result.matched:
                details = {"host": host, "port": port, "matched_indicator": result.matched_indicator}
                event = self.logger.log_event(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    description=f"{rule.description} (target: {host}:{port or '?'})",
                    details=details,
                    source_process=process,
                    source_pid=pid,
                )
                events.append(event)

        return events

    def check_file_access(
        self,
        file_path: str,
        access_type: str = "read",
        process: str = None,
        pid: int = None,
    ) -> List[Event]:
        """
        Check whether a file access violates any rule

        Args:
            file_path: Path of the accessed file
            access_type: Type of access (read/write/delete)
            process: Name of the process accessing the file
            pid: PID of the process accessing the file
        """
        events = []
        file_rules = [r for r in self.rules if r.category in (RuleCategory.FILE_ACCESS, RuleCategory.PRIVACY, RuleCategory.HONEYPOT)]

        for rule in file_rules:
            result = self._match_indicators(file_path, rule.indicators)
            if result.matched:
                is_honeypot = rule.category == RuleCategory.HONEYPOT
                details = {
                    "file_path": file_path,
                    "access_type": access_type,
                    "matched_indicator": result.matched_indicator,
                }
                event = self.logger.log_event(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    description=f"{rule.description} (file: {file_path}, access: {access_type})",
                    details=details,
                    source_process=process,
                    source_pid=pid,
                    is_honeypot_trigger=is_honeypot,
                )
                events.append(event)

        return events

    def check_process_activity(
        self,
        activity: str,
        process: str = None,
        pid: int = None,
        details: dict = None,
    ) -> List[Event]:
        """
        Check whether a process activity violates any rule

        Args:
            activity: Activity description or command string
            process: Process name
            pid: Process ID
            details: Additional detail information
        """
        events = []
        proc_rules = [r for r in self.rules if r.category in (RuleCategory.PROCESS, RuleCategory.TRACKING, RuleCategory.RESOURCE_ABUSE)]

        for rule in proc_rules:
            result = self._match_indicators(activity, rule.indicators)
            if result.matched:
                event_details = details or {}
                event_details["activity"] = activity
                event_details["matched_indicator"] = result.matched_indicator
                event = self.logger.log_event(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    description=f"{rule.description} (activity: {activity})",
                    details=event_details,
                    source_process=process,
                    source_pid=pid,
                )
                events.append(event)

        return events

    def check_raw_event(
        self,
        event_data: str,
        process: str = None,
        pid: int = None,
        details: dict = None,
    ) -> List[Event]:
        """
        Match raw event data against all rules

        Args:
            event_data: Raw event data string
            process: Related process name
            pid: Related process ID
            details: Additional detail information
        """
        events = []

        for rule in self.rules:
            result = self._match_indicators(event_data, rule.indicators)
            if result.matched:
                is_honeypot = rule.category == RuleCategory.HONEYPOT
                event_details = details or {}
                event_details["raw_event"] = event_data[:500]  # Truncate for storage
                event_details["matched_indicator"] = result.matched_indicator
                event = self.logger.log_event(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    description=rule.description,
                    details=event_details,
                    source_process=process,
                    source_pid=pid,
                    is_honeypot_trigger=is_honeypot,
                )
                events.append(event)

        return events

    def _match_indicators(self, data: str, indicators: List[str]) -> DetectionResult:
        """
        Match data against a list of indicators.

        Supports wildcard (*) and plain substring matching.
        """
        data_lower = data.lower()

        for indicator in indicators:
            indicator_lower = indicator.lower()

            if "*" in indicator_lower:
                pattern = re.escape(indicator_lower).replace(r"\*", ".*")
                if re.search(pattern, data_lower):
                    return DetectionResult(matched=True, matched_indicator=indicator)
            elif indicator_lower in data_lower:
                return DetectionResult(matched=True, matched_indicator=indicator)

        return DetectionResult(matched=False)

    def get_active_rules_count(self) -> int:
        """Return the number of active rules"""
        return len(self.rules)

    def get_rules_summary(self) -> dict:
        """Return a summary of active rules"""
        summary = {
            "total": len(self.rules),
            "by_severity": {},
            "by_category": {},
        }
        for rule in self.rules:
            sev = rule.severity.value
            cat = rule.category.value
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1
        return summary
