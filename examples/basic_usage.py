"""
ClawPot basic usage examples

Demonstrates how to use ClawPot to monitor OpenClaw illegal behavior.
"""

from clawpot.monitor import ClawPotMonitor, MonitorConfig
from clawpot.rules.openclaw_rules import Severity
from clawpot.report.reporter import Reporter


def example_basic_monitoring():
    """Example 1: Basic monitoring"""
    print("=" * 60)
    print("Example 1: Basic Monitoring")
    print("=" * 60)

    config = MonitorConfig(
        target_process="openclaw",
        verbose=True,
        alert_on_severity=Severity.MEDIUM,
    )
    monitor = ClawPotMonitor(config=config)

    # Register a custom alert handler
    def my_alert_handler(event):
        print(f"  [custom alert] [{event.rule_id}] {event.rule_name}")

    monitor.add_alert_callback(my_alert_handler)

    # Start monitoring without deploying honeypots (demo only)
    monitor.start(deploy_honeypots=False)

    print("\n[*] Simulating OpenClaw illegal behaviors...\n")

    print("[sim] OpenClaw connecting to telemetry server...")
    events = monitor.report_network_event(
        host="telemetry.openclaw.io",
        port=443,
        process="openclaw",
        pid=12345,
    )
    print(f"  -> {len(events)} violation(s) detected\n")

    print("[sim] OpenClaw reading browser cookies...")
    events = monitor.report_file_event(
        file_path="/home/user/.mozilla/firefox/abc123/cookies.sqlite",
        access_type="read",
        process="openclaw",
        pid=12345,
    )
    print(f"  -> {len(events)} violation(s) detected\n")

    print("[sim] OpenClaw installing keyboard hook...")
    events = monitor.report_process_event(
        activity="keyboard_hook installed via XGrabKeyboard",
        process="openclaw",
        pid=12345,
    )
    print(f"  -> {len(events)} violation(s) detected\n")

    print("[sim] OpenClaw capturing screen...")
    events = monitor.report_process_event(
        activity="screen_capture via XGetImage",
        process="openclaw",
        pid=12345,
    )
    print(f"  -> {len(events)} violation(s) detected\n")

    print("[sim] OpenClaw installing persistence...")
    events = monitor.report_process_event(
        activity="writing to /etc/cron.d/ for persistence",
        process="openclaw",
        pid=12345,
    )
    print(f"  -> {len(events)} violation(s) detected\n")

    monitor.stop()

    print("\n" + "=" * 60)
    print("Generating report...")
    print("=" * 60)
    reporter = Reporter(monitor.logger)
    print(reporter.generate_text_report())

    return monitor


def example_honeypot():
    """Example 2: Honeypot detection"""
    print("\n" + "=" * 60)
    print("Example 2: Honeypot Detection")
    print("=" * 60)

    monitor = ClawPotMonitor()
    monitor.start(deploy_honeypots=True)

    print("\n[sim] OpenClaw scanning and accessing honeypot bait...")
    events = monitor.report_file_event(
        file_path=str(monitor.honeypot.honeypot_dir / "clawpot_honey_credentials.json"),
        access_type="read",
        process="openclaw",
        pid=12345,
    )
    print(f"  -> {len(events)} violation(s) detected")

    honeypot_events = monitor.get_events(honeypot_only=True)
    if honeypot_events:
        print("\n[!] HONEYPOT TRIGGERED — OpenClaw accessed a bait file.")
        print("    This is direct evidence of illegal behavior.")

    monitor.stop()
    monitor.honeypot.remove_all()


def example_custom_rules():
    """Example 3: Custom detection rules"""
    print("\n" + "=" * 60)
    print("Example 3: Custom Detection Rules")
    print("=" * 60)

    from clawpot.rules.openclaw_rules import Rule, Severity, RuleCategory
    from clawpot.logger import ClawPotLogger
    from clawpot.detector import Detector

    logger = ClawPotLogger()

    custom_rule = Rule(
        rule_id="CUSTOM-001",
        name="Custom Rule: Sensitive Directory Access",
        description="OpenClaw is accessing a user-defined sensitive directory",
        category=RuleCategory.FILE_ACCESS,
        severity=Severity.HIGH,
        indicators=["/my/sensitive/data/"],
        action="alert",
    )

    detector = Detector(logger=logger, custom_rules=[custom_rule])
    print(f"Total active rules (including custom): {detector.get_active_rules_count()}")

    events = detector.check_file_access(
        file_path="/my/sensitive/data/important.db",
        access_type="read",
        process="openclaw",
    )
    print(f"Result: {len(events)} event(s) detected (custom rule triggered)")


if __name__ == "__main__":
    monitor = example_basic_monitoring()
    example_honeypot()
    example_custom_rules()

    print("\n[OK] All examples completed.")
