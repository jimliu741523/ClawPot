"""
ClawPot 命令列介面

提供使用者友善的 CLI 操作介面。
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
    """啟動 ClawPot 監控，然後執行目標程式（OpenClaw）"""
    if not args.command_args:
        print("❌ 請指定要執行的程式，例如:")
        print("   clawpot run openclaw")
        print("   clawpot run openclaw --some-flag")
        print("   clawpot run -- /path/to/openclaw arg1 arg2")
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
    """啟動即時監控"""
    config = MonitorConfig(
        target_pid=args.pid,
        target_process=args.process,
        verbose=args.verbose,
        poll_interval=args.interval,
        alert_on_severity=Severity(args.alert_level),
    )
    monitor = ClawPotMonitor(config=config)
    monitor.start(deploy_honeypots=not args.no_honeypot)

    # 保持執行直到中斷
    import time
    try:
        while monitor._running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        monitor.stop()


def cmd_report(args):
    """產生分析報告"""
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
    """查看偵測事件"""
    logger = ClawPotLogger()
    reporter = Reporter(logger)

    severity = Severity(args.severity) if args.severity else None
    events = logger.get_events(severity=severity, honeypot_only=args.honeypot_only)

    if not events:
        print("📭 目前無事件記錄。")
        print("   請先使用 'clawpot monitor' 啟動監控。")
        return

    print(f"\n找到 {len(events)} 個事件:")
    reporter.print_events_table(events)


def cmd_honeypot(args):
    """管理蜜罐誘餌"""
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
            print("🪤 目前無已部署的蜜罐。")
            print("   使用 'clawpot honeypot deploy' 部署蜜罐。")
            return

        print(f"\n已部署蜜罐 ({len(status)} 個):")
        print("-" * 70)
        for hp in status:
            triggered_str = f"✅ 已觸發 {hp['trigger_count']} 次" if hp["triggered"] else "⏳ 未觸發"
            print(f"  類型: {hp['bait_type']}")
            print(f"  路徑: {hp['path']}")
            print(f"  狀態: {triggered_str}")
            if hp["last_triggered"]:
                print(f"  最後觸發: {hp['last_triggered']}")
            print()

    elif args.honeypot_cmd == "remove":
        confirm = input("⚠️  確定要移除所有蜜罐誘餌? (y/N): ")
        if confirm.lower() == "y":
            honeypot.remove_all()
            print("✅ 已移除所有蜜罐。")
        else:
            print("已取消。")

    else:
        print("請指定子命令: deploy | status | remove")


def cmd_rules(args):
    """查看偵測規則"""
    from .rules.openclaw_rules import OPENCLAW_RULES, RuleCategory

    rules = OPENCLAW_RULES
    if args.category:
        try:
            cat = RuleCategory(args.category)
            rules = [r for r in rules if r.category == cat]
        except ValueError:
            print(f"❌ 未知分類: {args.category}")
            return

    if args.severity:
        try:
            sev = Severity(args.severity)
            rules = [r for r in rules if r.severity == sev]
        except ValueError:
            print(f"❌ 未知嚴重程度: {args.severity}")
            return

    severity_icons = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}

    print(f"\nClawPot 偵測規則 (共 {len(rules)} 條):")
    print("-" * 80)
    for rule in rules:
        icon = severity_icons.get(rule.severity.value, "⚪")
        status = "✅" if rule.enabled else "❌"
        print(f"  {status} {icon} [{rule.rule_id}] {rule.name}")
        print(f"       分類: {rule.category.value} | 嚴重: {rule.severity.value}")
        print(f"       說明: {rule.description}")
        print()


def build_parser() -> argparse.ArgumentParser:
    """建立命令列解析器"""
    parser = argparse.ArgumentParser(
        prog="clawpot",
        description="ClawPot - OpenClaw 非法行為監控蜜罐系統",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
範例:
  clawpot run openclaw               # 啟動監控，然後執行 openclaw
  clawpot run -- openclaw --flag     # 傳遞參數給 openclaw
  clawpot run -v openclaw            # 詳細模式（顯示所有檔案/網路活動）
  clawpot run --no-report openclaw   # 結束後不顯示報告
  clawpot monitor                    # 獨立監控模式（不啟動任何程式）
  clawpot monitor --pid 1234         # 監控指定 PID
  clawpot report                     # 產生文字報告
  clawpot events --severity critical # 只看嚴重事件
  clawpot honeypot deploy            # 部署蜜罐
  clawpot rules                      # 查看所有規則
        """,
    )
    parser.add_argument("--version", action="version", version=f"ClawPot {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # run 子命令（主要使用方式）
    run_parser = subparsers.add_parser(
        "run",
        help="啟動 ClawPot 監控，然後執行目標程式",
        description="先部署蜜罐並啟動監控，再以子進程方式執行目標程式（OpenClaw），全程追蹤其行為。",
    )
    run_parser.add_argument("command_args", nargs=argparse.REMAINDER, help="要執行的程式與參數")
    run_parser.add_argument("--verbose", "-v", action="store_true", help="顯示所有檔案存取與網路連線")
    run_parser.add_argument("--no-honeypot", action="store_true", help="不部署蜜罐誘餌")
    run_parser.add_argument("--no-report", action="store_true", help="結束後不顯示報告")
    run_parser.add_argument(
        "--alert-level",
        default="medium",
        choices=["low", "medium", "high", "critical"],
        help="警報觸發門檻（預設: medium）",
    )
    run_parser.add_argument("--interval", type=float, default=1.0, help="監控輪詢間隔秒數（預設: 1.0）")
    run_parser.add_argument(
        "--report-format",
        default="text",
        choices=["text", "json"],
        help="結束報告格式（預設: text）",
    )

    # monitor 子命令
    monitor_parser = subparsers.add_parser("monitor", help="啟動即時監控")
    monitor_parser.add_argument("--pid", type=int, help="監控指定 PID")
    monitor_parser.add_argument("--process", default="openclaw", help="監控進程名稱")
    monitor_parser.add_argument("--verbose", "-v", action="store_true", help="詳細輸出")
    monitor_parser.add_argument("--interval", type=float, default=1.0, help="輪詢間隔（秒）")
    monitor_parser.add_argument("--no-honeypot", action="store_true", help="不部署蜜罐")
    monitor_parser.add_argument(
        "--alert-level",
        default="medium",
        choices=["low", "medium", "high", "critical"],
        help="警報觸發門檻",
    )

    # report 子命令
    report_parser = subparsers.add_parser("report", help="產生分析報告")
    report_parser.add_argument(
        "--format", default="text", choices=["text", "json"], help="輸出格式"
    )
    report_parser.add_argument("--output", "-o", help="輸出檔案路徑")

    # events 子命令
    events_parser = subparsers.add_parser("events", help="查看偵測事件")
    events_parser.add_argument(
        "--severity", choices=["low", "medium", "high", "critical"], help="篩選嚴重程度"
    )
    events_parser.add_argument("--honeypot-only", action="store_true", help="只顯示蜜罐觸發事件")

    # honeypot 子命令
    honeypot_parser = subparsers.add_parser("honeypot", help="管理蜜罐誘餌")
    hp_sub = honeypot_parser.add_subparsers(dest="honeypot_cmd")
    deploy_parser = hp_sub.add_parser("deploy", help="部署蜜罐誘餌")
    deploy_parser.add_argument(
        "--type",
        choices=["credentials", "wallet", "personal_data", "session"],
        help="指定部署類型",
    )
    hp_sub.add_parser("status", help="查看蜜罐狀態")
    hp_sub.add_parser("remove", help="移除所有蜜罐")

    # rules 子命令
    rules_parser = subparsers.add_parser("rules", help="查看偵測規則")
    rules_parser.add_argument(
        "--category",
        choices=["network", "file_access", "privacy", "resource_abuse", "tracking", "process", "honeypot"],
        help="篩選規則分類",
    )
    rules_parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        help="篩選嚴重程度",
    )

    return parser


def main():
    """CLI 入口點"""
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
