"""
ClawPot 行為偵測器

分析 OpenClaw 的行為並與規則庫比對，識別非法活動。
"""

import re
from typing import List, Optional, Tuple

from .rules.openclaw_rules import OPENCLAW_RULES, Rule, Severity, RuleCategory
from .logger import ClawPotLogger, Event


class DetectionResult:
    """偵測結果"""

    def __init__(self, matched: bool, rule: Optional[Rule] = None, matched_indicator: str = ""):
        self.matched = matched
        self.rule = rule
        self.matched_indicator = matched_indicator

    def __bool__(self):
        return self.matched


class Detector:
    """
    OpenClaw 非法行為偵測器

    將觀察到的行為與規則庫進行比對，判斷是否為非法活動。
    """

    def __init__(self, logger: ClawPotLogger, custom_rules: List[Rule] = None):
        self.logger = logger
        self.rules = list(OPENCLAW_RULES)
        if custom_rules:
            self.rules.extend(custom_rules)
        # 只保留啟用的規則
        self.rules = [r for r in self.rules if r.enabled]

    def check_network_connection(
        self,
        host: str,
        port: int = None,
        process: str = None,
        pid: int = None,
    ) -> List[Event]:
        """
        檢查網路連線是否違規

        Args:
            host: 目標主機名稱或 IP
            port: 目標連接埠
            process: 發起連線的進程名稱
            pid: 發起連線的進程 ID
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
                    description=f"{rule.description} (連線目標: {host}:{port or '?'})",
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
        檢查檔案存取是否違規

        Args:
            file_path: 被存取的檔案路徑
            access_type: 存取類型 (read/write/delete)
            process: 發起存取的進程名稱
            pid: 發起存取的進程 ID
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
                    description=f"{rule.description} (檔案: {file_path}, 操作: {access_type})",
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
        檢查進程活動是否違規

        Args:
            activity: 活動描述或命令
            process: 進程名稱
            pid: 進程 ID
            details: 額外詳細資訊
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
                    description=f"{rule.description} (活動: {activity})",
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
        對原始事件資料進行全規則比對

        Args:
            event_data: 原始事件資料字串
            process: 相關進程名稱
            pid: 相關進程 ID
            details: 額外詳細資訊
        """
        events = []

        for rule in self.rules:
            result = self._match_indicators(event_data, rule.indicators)
            if result.matched:
                is_honeypot = rule.category == RuleCategory.HONEYPOT
                event_details = details or {}
                event_details["raw_event"] = event_data[:500]  # 限制長度
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
        將資料與指標列表進行比對

        支援萬用字元（*）和一般字串比對。
        """
        data_lower = data.lower()

        for indicator in indicators:
            indicator_lower = indicator.lower()

            # 處理萬用字元
            if "*" in indicator_lower:
                pattern = re.escape(indicator_lower).replace(r"\*", ".*")
                if re.search(pattern, data_lower):
                    return DetectionResult(matched=True, matched_indicator=indicator)
            # 一般字串包含比對
            elif indicator_lower in data_lower:
                return DetectionResult(matched=True, matched_indicator=indicator)

        return DetectionResult(matched=False)

    def get_active_rules_count(self) -> int:
        """取得啟用規則數量"""
        return len(self.rules)

    def get_rules_summary(self) -> dict:
        """取得規則摘要"""
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
