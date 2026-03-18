"""
OpenClaw 非法行為偵測規則庫

定義用於識別 OpenClaw 非法行為的規則集合。
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional


class Severity(Enum):
    """事件嚴重程度"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleCategory(Enum):
    """規則分類"""
    NETWORK = "network"               # 網路活動
    FILE_ACCESS = "file_access"       # 檔案存取
    PRIVACY = "privacy"               # 隱私侵犯
    RESOURCE_ABUSE = "resource_abuse" # 資源濫用
    TRACKING = "tracking"             # 行為追蹤
    PROCESS = "process"               # 進程活動
    HONEYPOT = "honeypot"             # 蜜罐觸發


@dataclass
class Rule:
    """偵測規則定義"""
    rule_id: str
    name: str
    description: str
    category: RuleCategory
    severity: Severity
    indicators: List[str]           # 觸發指標（關鍵字、IP、路徑等）
    action: str = "alert"           # alert | block | log
    references: List[str] = field(default_factory=list)
    enabled: bool = True


# OpenClaw 非法行為規則庫
OPENCLAW_RULES: List[Rule] = [

    # ─── 網路連線規則 ──────────────────────────────────────────────────────────

    Rule(
        rule_id="OC-NET-001",
        name="未授權外部連線",
        description="OpenClaw 嘗試連線至非必要的外部伺服器，可能涉及資料外洩",
        category=RuleCategory.NETWORK,
        severity=Severity.HIGH,
        indicators=[
            "openclaw.io",
            "api.openclaw",
            "telemetry.openclaw",
            "collect.openclaw",
            "analytics.openclaw",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-NET-002",
        name="可疑 DNS 查詢",
        description="OpenClaw 發起可疑的 DNS 查詢，可能透過 DNS 進行資料回傳",
        category=RuleCategory.NETWORK,
        severity=Severity.MEDIUM,
        indicators=[
            "*.openclaw.io",
            "*.claw-track.com",
            "*.clawdata.net",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-NET-003",
        name="未加密資料傳輸",
        description="OpenClaw 透過 HTTP（非 HTTPS）傳輸使用者資料",
        category=RuleCategory.NETWORK,
        severity=Severity.HIGH,
        indicators=[
            "http://",
            "port:80",
            "unencrypted_payload",
        ],
        action="alert",
    ),

    # ─── 隱私侵犯規則 ──────────────────────────────────────────────────────────

    Rule(
        rule_id="OC-PRIV-001",
        name="瀏覽器 Cookie 存取",
        description="OpenClaw 嘗試讀取瀏覽器 Cookie 資料，違反使用者隱私",
        category=RuleCategory.PRIVACY,
        severity=Severity.CRITICAL,
        indicators=[
            "Cookies/",
            "cookies.sqlite",
            "chrome/Default/Cookies",
            "firefox/cookies.sqlite",
            "edge/Default/Cookies",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-PRIV-002",
        name="密碼庫存取",
        description="OpenClaw 嘗試存取系統密碼儲存區或瀏覽器儲存的密碼",
        category=RuleCategory.PRIVACY,
        severity=Severity.CRITICAL,
        indicators=[
            "Login Data",
            "keychain",
            "Keystore",
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            "wallet.dat",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-PRIV-003",
        name="剪貼簿監聽",
        description="OpenClaw 持續監聽系統剪貼簿內容",
        category=RuleCategory.PRIVACY,
        severity=Severity.HIGH,
        indicators=[
            "clipboard_read",
            "xclip",
            "xsel",
            "pbpaste",
        ],
        action="alert",
    ),

    # ─── 檔案存取規則 ──────────────────────────────────────────────────────────

    Rule(
        rule_id="OC-FILE-001",
        name="系統設定檔未授權存取",
        description="OpenClaw 存取超出其運作範圍的系統設定檔",
        category=RuleCategory.FILE_ACCESS,
        severity=Severity.MEDIUM,
        indicators=[
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "C:\\Windows\\System32\\",
            "C:\\Users\\",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-FILE-002",
        name="蜜罐誘餌檔案觸發",
        description="OpenClaw 存取了 ClawPot 設置的蜜罐誘餌檔案",
        category=RuleCategory.HONEYPOT,
        severity=Severity.CRITICAL,
        indicators=[
            "clawpot_honey_",
            ".clawpot_bait",
            "fake_credentials.txt",
            "honeypot_data.json",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-FILE-003",
        name="大量檔案掃描",
        description="OpenClaw 在短時間內掃描大量使用者檔案",
        category=RuleCategory.FILE_ACCESS,
        severity=Severity.HIGH,
        indicators=[
            "mass_file_scan",
            "recursive_read",
        ],
        action="alert",
    ),

    # ─── 資源濫用規則 ──────────────────────────────────────────────────────────

    Rule(
        rule_id="OC-RES-001",
        name="CPU 異常高使用率",
        description="OpenClaw 持續佔用過高 CPU 資源，可能進行加密貨幣挖礦或暴力破解",
        category=RuleCategory.RESOURCE_ABUSE,
        severity=Severity.MEDIUM,
        indicators=[
            "cpu_usage>80%",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-RES-002",
        name="記憶體異常佔用",
        description="OpenClaw 記憶體使用量異常增長，可能存在資料囤積行為",
        category=RuleCategory.RESOURCE_ABUSE,
        severity=Severity.LOW,
        indicators=[
            "memory_growth_anomaly",
        ],
        action="log",
    ),

    # ─── 行為追蹤規則 ──────────────────────────────────────────────────────────

    Rule(
        rule_id="OC-TRACK-001",
        name="鍵盤記錄行為",
        description="OpenClaw 嘗試記錄使用者鍵盤輸入",
        category=RuleCategory.TRACKING,
        severity=Severity.CRITICAL,
        indicators=[
            "keyboard_hook",
            "SetWindowsHookEx",
            "XGrabKeyboard",
            "CGEventTapCreate",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-TRACK-002",
        name="螢幕截圖行為",
        description="OpenClaw 在使用者未知情下進行螢幕截圖",
        category=RuleCategory.TRACKING,
        severity=Severity.HIGH,
        indicators=[
            "screenshot",
            "screen_capture",
            "BitBlt",
            "XGetImage",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-TRACK-003",
        name="使用者行為分析回傳",
        description="OpenClaw 將使用者操作行為資料回傳至外部伺服器",
        category=RuleCategory.TRACKING,
        severity=Severity.HIGH,
        indicators=[
            "behavior_upload",
            "user_analytics",
            "usage_telemetry",
        ],
        action="alert",
    ),

    # ─── 進程活動規則 ──────────────────────────────────────────────────────────

    Rule(
        rule_id="OC-PROC-001",
        name="可疑子進程產生",
        description="OpenClaw 產生非預期的子進程，可能執行惡意程式碼",
        category=RuleCategory.PROCESS,
        severity=Severity.HIGH,
        indicators=[
            "cmd.exe",
            "powershell.exe",
            "/bin/sh",
            "/bin/bash",
            "subprocess_spawn",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-PROC-002",
        name="持久化機制安裝",
        description="OpenClaw 嘗試在系統中安裝持久化機制（開機自動啟動）",
        category=RuleCategory.PROCESS,
        severity=Severity.CRITICAL,
        indicators=[
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "LaunchAgents",
            "LaunchDaemons",
            "/etc/cron.d/",
            "systemd service install",
        ],
        action="alert",
    ),
]


def get_rules_by_category(category: RuleCategory) -> List[Rule]:
    """依分類取得規則"""
    return [r for r in OPENCLAW_RULES if r.category == category and r.enabled]


def get_rules_by_severity(severity: Severity) -> List[Rule]:
    """依嚴重程度取得規則"""
    return [r for r in OPENCLAW_RULES if r.severity == severity and r.enabled]


def get_rule_by_id(rule_id: str) -> Optional[Rule]:
    """依 ID 取得規則"""
    for rule in OPENCLAW_RULES:
        if rule.rule_id == rule_id:
            return rule
    return None
