"""
ClawPot command-line interface
"""

import argparse
import sys
from pathlib import Path

from . import __version__
from .monitor import ClawPotMonitor, MonitorConfig
from .logger import ClawPotLogger
from .report.reporter import Reporter
from .honeypot import HoneypotManager
from .rules.openclaw_rules import Severity
from .runner import ClawPotRunner


def cmd_run(args):
    """Start ClawPot monitoring, then launch the target program (OpenClaw)"""
    if not args.command_args:
        print("Error: please specify the program to run, e.g.:")
        print("  clawpot run openclaw")
        print("  clawpot run openclaw --some-flag")
        print("  clawpot run -- /path/to/openclaw arg1 arg2")
        sys.exit(1)

    runner = ClawPotRunner(
        command=args.command_args,
        verbose=args.verbose,
        no_honeypot=args.no_honeypot,
        alert_on_severity=Severity(args.alert_level),
        poll_interval=args.interval,
        report_on_exit=not args.no_report,
        report_format=args.report_format,
    )
    exit_code = runner.run()
    sys.exit(exit_code)


def cmd_monitor(args):
    """Start standalone monitoring (without launching any program)"""
    config = MonitorConfig(
        target_pid=args.pid,
        target_process=args.process,
        verbose=args.verbose,
        poll_interval=args.interval,
        alert_on_severity=Severity(args.alert_level),
    )
    monitor = ClawPotMonitor(config=config)
    monitor.start(deploy_honeypots=not args.no_honeypot)

    import time
    try:
        while monitor._running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        monitor.stop()


def cmd_report(args):
    """Generate a behavior analysis report"""
    logger = ClawPotLogger()
    reporter = Reporter(logger)

    output_path = Path(args.output) if args.output else None

    if args.format == "json":
        report = reporter.generate_json_report(output_path=output_path)
        if not output_path:
            import json
            print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        report = reporter.generate_text_report(output_path=output_path)
        if not output_path:
            print(report)


def cmd_events(args):
    """View detected events"""
    logger = ClawPotLogger()
    reporter = Reporter(logger)

    severity = Severity(args.severity) if args.severity else None
    events = logger.get_events(severity=severity, honeypot_only=args.honeypot_only)

    if not events:
        print("No events recorded.")
        print("Start monitoring first with: clawpot run <program>")
        return

    print(f"\n{len(events)} event(s) found:")
    reporter.print_events_table(events)


def cmd_honeypot(args):
    """Manage honeypot bait files"""
    logger = ClawPotLogger()
    honeypot = HoneypotManager(logger=logger)

    if args.honeypot_cmd == "deploy":
        if args.type:
            honeypot.deploy(args.type)
        else:
            honeypot.deploy_all()

    elif args.honeypot_cmd == "status":
        status = honeypot.get_status()
        if not status:
            print("No honeypots deployed.")
            print("Run: clawpot honeypot deploy")
            return

        print(f"\nDeployed honeypots ({len(status)}):")
        print("-" * 70)
        for hp in status:
            triggered_str = f"TRIGGERED ({hp['trigger_count']}x)" if hp["triggered"] else "waiting"
            print(f"  Type        : {hp['bait_type']}")
            print(f"  Path        : {hp['path']}")
            print(f"  Status      : {triggered_str}")
            if hp["last_triggered"]:
                print(f"  Last trigger: {hp['last_triggered']}")
            print()

    elif args.honeypot_cmd == "remove":
        confirm = input("Remove all honeypot files? (y/N): ")
        if confirm.lower() == "y":
            honeypot.remove_all()
            print("All honeypots removed.")
        else:
            print("Cancelled.")

    else:
        print("Specify a subcommand: deploy | status | remove")


def cmd_rules(args):
    """List detection rules"""
    from .rules.openclaw_rules import OPENCLAW_RULES, RuleCategory

    rules = OPENCLAW_RULES
    if args.category:
        try:
            cat = RuleCategory(args.category)
            rules = [r for r in rules if r.category == cat]
        except ValueError:
            print(f"Unknown category: {args.category}")
            return

    if args.severity:
        try:
            sev = Severity(args.severity)
            rules = [r for r in rules if r.severity == sev]
        except ValueError:
            print(f"Unknown severity: {args.severity}")
            return

    severity_icons = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}

    print(f"\nClawPot Detection Rules ({len(rules)} total):")
    print("-" * 80)
    for rule in rules:
        icon = severity_icons.get(rule.severity.value, "⚪")
        status = "[on] " if rule.enabled else "[off]"
        print(f"  {status} {icon} [{rule.rule_id}] {rule.name}")
        print(f"        category: {rule.category.value} | severity: {rule.severity.value}")
        print(f"        {rule.description}")
        print()


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser"""
    parser = argparse.ArgumentParser(
        prog="clawpot",
        description="ClawPot - Honeypot monitoring system for detecting OpenClaw illegal activity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  clawpot run openclaw               # Monitor then launch openclaw
  clawpot run -- openclaw --flag     # Pass arguments to openclaw
  clawpot run -v openclaw            # Verbose: show all file/network activity
  clawpot run --no-report openclaw   # Skip final report
  clawpot monitor                    # Standalone monitor (no program launched)
  clawpot monitor --pid 1234         # Monitor a specific PID
  clawpot report                     # Generate text report
  clawpot events --severity critical # Show only critical events
  clawpot honeypot deploy            # Deploy honeypot bait files
  clawpot rules                      # List all detection rules
        """,
    )
    parser.add_argument("--version", action="version", version=f"ClawPot {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="subcommand")

    # run subcommand (primary usage)
    run_parser = subparsers.add_parser(
        "run",
        help="Start monitoring, then launch the target program",
        description="Deploy honeypots and start monitoring, then launch the target program as a subprocess.",
    )
    run_parser.add_argument("command_args", nargs=argparse.REMAINDER, help="Program and arguments to run")
    run_parser.add_argument("--verbose", "-v", action="store_true", help="Show all file access and network activity")
    run_parser.add_argument("--no-honeypot", action="store_true", help="Do not deploy honeypot bait files")
    run_parser.add_argument("--no-report", action="store_true", help="Do not print report on exit")
    run_parser.add_argument(
        "--alert-level",
        default="medium",
        choices=["low", "medium", "high", "critical"],
        help="Minimum severity level for alerts (default: medium)",
    )
    run_parser.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds (default: 1.0)")
    run_parser.add_argument(
        "--report-format",
        default="text",
        choices=["text", "json"],
        help="Format of the final report (default: text)",
    )

    # monitor subcommand
    monitor_parser = subparsers.add_parser("monitor", help="Standalone monitoring mode")
    monitor_parser.add_argument("--pid", type=int, help="Monitor a specific PID")
    monitor_parser.add_argument("--process", default="openclaw", help="Target process name")
    monitor_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    monitor_parser.add_argument("--interval", type=float, default=1.0, help="Polling interval (seconds)")
    monitor_parser.add_argument("--no-honeypot", action="store_true", help="Do not deploy honeypots")
    monitor_parser.add_argument(
        "--alert-level",
        default="medium",
        choices=["low", "medium", "high", "critical"],
        help="Alert threshold",
    )

    # report subcommand
    report_parser = subparsers.add_parser("report", help="Generate analysis report")
    report_parser.add_argument(
        "--format", default="text", choices=["text", "json"], help="Output format"
    )
    report_parser.add_argument("--output", "-o", help="Output file path")

    # events subcommand
    events_parser = subparsers.add_parser("events", help="View detected events")
    events_parser.add_argument(
        "--severity", choices=["low", "medium", "high", "critical"], help="Filter by severity"
    )
    events_parser.add_argument("--honeypot-only", action="store_true", help="Show only honeypot triggers")

    # honeypot subcommand
    honeypot_parser = subparsers.add_parser("honeypot", help="Manage honeypot bait files")
    hp_sub = honeypot_parser.add_subparsers(dest="honeypot_cmd")
    deploy_parser = hp_sub.add_parser("deploy", help="Deploy bait files")
    deploy_parser.add_argument(
        "--type",
        choices=["credentials", "wallet", "personal_data", "session"],
        help="Specific bait type to deploy",
    )
    hp_sub.add_parser("status", help="Show honeypot status")
    hp_sub.add_parser("remove", help="Remove all honeypots")

    # rules subcommand
    rules_parser = subparsers.add_parser("rules", help="List detection rules")
    rules_parser.add_argument(
        "--category",
        choices=["network", "file_access", "privacy", "resource_abuse", "tracking", "process", "honeypot"],
        help="Filter by category",
    )
    rules_parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        help="Filter by severity",
    )

    return parser


def main():
    """CLI entry point"""
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    commands = {
        "run": cmd_run,
        "monitor": cmd_monitor,
        "report": cmd_report,
        "events": cmd_events,
        "honeypot": cmd_honeypot,
        "rules": cmd_rules,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
