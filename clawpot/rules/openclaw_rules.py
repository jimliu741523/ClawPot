"""
ClawPot detection rules library

Two rule sets:
- OPENCLAW_RULES : rules specific to known OpenClaw illegal behaviors
- GENERAL_RULES  : rules that apply to *any* monitored process (including Claude Code)
- ALL_RULES      : combined set used by default
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional


class Severity(Enum):
    """Event severity level"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleCategory(Enum):
    """Rule category"""
    NETWORK = "network"               # Network activity
    FILE_ACCESS = "file_access"       # File access
    PRIVACY = "privacy"               # Privacy violation
    RESOURCE_ABUSE = "resource_abuse" # Resource abuse
    TRACKING = "tracking"             # Behavior tracking
    PROCESS = "process"               # Process activity
    HONEYPOT = "honeypot"             # Honeypot trigger


@dataclass
class Rule:
    """Detection rule definition"""
    rule_id: str
    name: str
    description: str
    category: RuleCategory
    severity: Severity
    indicators: List[str]           # Trigger indicators (keywords, IPs, paths, etc.)
    action: str = "alert"           # alert | block | log
    references: List[str] = field(default_factory=list)
    enabled: bool = True


# OpenClaw illegal behavior rule set
OPENCLAW_RULES: List[Rule] = [

    # ─── Network rules ────────────────────────────────────────────────────────

    Rule(
        rule_id="OC-NET-001",
        name="Unauthorized External Connection",
        description="OpenClaw is attempting to connect to an external server, possibly for data exfiltration",
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
        name="Suspicious DNS Query",
        description="OpenClaw is making suspicious DNS queries, possibly using DNS to exfiltrate data",
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
        name="Unencrypted Data Transmission",
        description="OpenClaw is transmitting user data over HTTP (unencrypted)",
        category=RuleCategory.NETWORK,
        severity=Severity.HIGH,
        indicators=[
            "http://",
            "port:80",
            "unencrypted_payload",
        ],
        action="alert",
    ),

    # ─── Privacy rules ────────────────────────────────────────────────────────

    Rule(
        rule_id="OC-PRIV-001",
        name="Browser Cookie Access",
        description="OpenClaw is attempting to read browser cookie files, violating user privacy",
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
        name="Password Store Access",
        description="OpenClaw is attempting to access system password storage or browser-saved credentials",
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
        name="Clipboard Monitoring",
        description="OpenClaw is continuously monitoring the system clipboard",
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

    # ─── File access rules ────────────────────────────────────────────────────

    Rule(
        rule_id="OC-FILE-001",
        name="Unauthorized System File Access",
        description="OpenClaw is accessing system configuration files outside its operating scope",
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
        name="Honeypot Bait File Triggered",
        description="OpenClaw accessed a honeypot bait file planted by ClawPot",
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
        name="Mass File Scanning",
        description="OpenClaw is scanning a large number of user files in a short period",
        category=RuleCategory.FILE_ACCESS,
        severity=Severity.HIGH,
        indicators=[
            "mass_file_scan",
            "recursive_read",
        ],
        action="alert",
    ),

    # ─── Resource abuse rules ─────────────────────────────────────────────────

    Rule(
        rule_id="OC-RES-001",
        name="Abnormal CPU Usage",
        description="OpenClaw is continuously consuming excessive CPU, possibly mining cryptocurrency or brute-forcing",
        category=RuleCategory.RESOURCE_ABUSE,
        severity=Severity.MEDIUM,
        indicators=[
            "cpu_usage>80%",
        ],
        action="alert",
    ),

    Rule(
        rule_id="OC-RES-002",
        name="Abnormal Memory Growth",
        description="OpenClaw memory usage is growing anomalously, possibly hoarding data",
        category=RuleCategory.RESOURCE_ABUSE,
        severity=Severity.LOW,
        indicators=[
            "memory_growth_anomaly",
        ],
        action="log",
    ),

    # ─── Tracking rules ───────────────────────────────────────────────────────

    Rule(
        rule_id="OC-TRACK-001",
        name="Keylogging Behavior",
        description="OpenClaw is attempting to record user keyboard input",
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
        name="Screen Capture Behavior",
        description="OpenClaw is taking screenshots without the user's knowledge",
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
        name="Behavior Analytics Upload",
        description="OpenClaw is uploading user behavior data to an external server",
        category=RuleCategory.TRACKING,
        severity=Severity.HIGH,
        indicators=[
            "behavior_upload",
            "user_analytics",
            "usage_telemetry",
        ],
        action="alert",
    ),

    # ─── Process activity rules ───────────────────────────────────────────────

    Rule(
        rule_id="OC-PROC-001",
        name="Suspicious Child Process",
        description="OpenClaw spawned an unexpected child process, possibly executing malicious code",
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
        name="Persistence Mechanism Installation",
        description="OpenClaw is attempting to install a persistence mechanism (auto-start on boot)",
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



# ── General suspicious behavior rules (apply to any process) ─────────────────
#
# These rules are not OpenClaw-specific.
# They catch behaviors that are suspicious regardless of the target program,
# including Claude Code, electron apps, or any other software.

GENERAL_RULES: List[Rule] = [

    Rule(
        rule_id="GEN-NET-001",
        name="Connection to Ads / Tracking Network",
        description="Process is connecting to known advertising or user-tracking networks",
        category=RuleCategory.NETWORK,
        severity=Severity.MEDIUM,
        indicators=[
            "doubleclick.net",
            "googlesyndication.com",
            "facebook.com/tr",
            "segment.io",
            "mixpanel.com",
            "amplitude.com",
            "hotjar.com",
            "fullstory.com",
            "mouseflow.com",
        ],
        action="alert",
    ),

    Rule(
        rule_id="GEN-NET-002",
        name="Unexpected Data Upload",
        description="Process is uploading data to an external endpoint (large POST/PUT)",
        category=RuleCategory.NETWORK,
        severity=Severity.HIGH,
        indicators=[
            "upload",
            "exfil",
            "data_send",
            "report_data",
        ],
        action="alert",
    ),

    Rule(
        rule_id="GEN-PRIV-001",
        name="Browser Credential Access",
        description="Process accessed browser-stored passwords or session tokens",
        category=RuleCategory.PRIVACY,
        severity=Severity.CRITICAL,
        indicators=[
            "Login Data",
            "cookies.sqlite",
            "chrome/Default/Cookies",
            "Cookies/",
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            "keychain",
        ],
        action="alert",
    ),

    Rule(
        rule_id="GEN-PRIV-002",
        name="Environment Variable Secrets Access",
        description="Process read a file that likely contains API keys or secrets",
        category=RuleCategory.PRIVACY,
        severity=Severity.HIGH,
        indicators=[
            ".env",
            ".env.local",
            ".env.production",
            "secrets.yaml",
            "secrets.json",
            "credentials.json",
            ".aws/credentials",
            ".config/gcloud",
        ],
        action="alert",
    ),

    Rule(
        rule_id="GEN-FILE-001",
        name="Sensitive System File Access",
        description="Process accessed a sensitive system file outside its expected scope",
        category=RuleCategory.FILE_ACCESS,
        severity=Severity.MEDIUM,
        indicators=[
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "C:\\Windows\\System32\\config\\SAM",
        ],
        action="alert",
    ),

    Rule(
        rule_id="GEN-TRACK-001",
        name="Keylogging System Call",
        description="Process invoked a system-level keyboard capture API",
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
        rule_id="GEN-TRACK-002",
        name="Screen Capture",
        description="Process performed a screen capture without user interaction",
        category=RuleCategory.TRACKING,
        severity=Severity.HIGH,
        indicators=[
            "screenshot",
            "screen_capture",
            "BitBlt",
            "XGetImage",
            "CGWindowListCreateImage",
        ],
        action="alert",
    ),

    Rule(
        rule_id="GEN-PROC-001",
        name="Shell Spawned",
        description="Process spawned an interactive shell, which may indicate command injection",
        category=RuleCategory.PROCESS,
        severity=Severity.HIGH,
        indicators=[
            "/bin/sh",
            "/bin/bash",
            "/bin/zsh",
            "cmd.exe",
            "powershell.exe",
        ],
        action="alert",
    ),

    Rule(
        rule_id="GEN-HONEY-001",
        name="Honeypot Bait File Accessed",
        description="Process accessed a ClawPot honeypot bait file — confirmed suspicious behavior",
        category=RuleCategory.HONEYPOT,
        severity=Severity.CRITICAL,
        indicators=[
            "clawpot_honey_",
            ".clawpot_bait",
        ],
        action="alert",
    ),
]

# Combined rule set used by default
ALL_RULES: List[Rule] = OPENCLAW_RULES + GENERAL_RULES


def get_rules_by_category(category: RuleCategory) -> List[Rule]:
    """Get rules filtered by category"""
    return [r for r in OPENCLAW_RULES if r.category == category and r.enabled]


def get_rules_by_severity(severity: Severity) -> List[Rule]:
    """Get rules filtered by severity"""
    return [r for r in OPENCLAW_RULES if r.severity == severity and r.enabled]


def get_rule_by_id(rule_id: str) -> Optional[Rule]:
    """Get a rule by its ID"""
    for rule in OPENCLAW_RULES:
        if rule.rule_id == rule_id:
            return rule
    return None
