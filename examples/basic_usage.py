"""
ClawPot 基本使用範例

展示如何使用 ClawPot 監控 OpenClaw 的非法行為。
"""

from clawpot.monitor import ClawPotMonitor, MonitorConfig
from clawpot.rules.openclaw_rules import Severity
from clawpot.report.reporter import Reporter


def example_basic_monitoring():
    """基本監控範例"""
    print("=" * 60)
    print("範例 1: 基本監控")
    print("=" * 60)

    # 建立監控器
    config = MonitorConfig(
        target_process="openclaw",
        verbose=True,
        alert_on_severity=Severity.MEDIUM,
    )
    monitor = ClawPotMonitor(config=config)

    # 新增自訂警報處理
    def my_alert_handler(event):
        print(f"  🚨 自訂警報: [{event.rule_id}] {event.rule_name}")

    monitor.add_alert_callback(my_alert_handler)

    # 啟動監控（不部署蜜罐，僅作示範）
    monitor.start(deploy_honeypots=False)

    # 模擬 OpenClaw 的各種非法行為
    print("\n📋 模擬 OpenClaw 非法行為...")

    # 模擬 1: 惡意網路連線
    print("\n[模擬] OpenClaw 嘗試連線至追蹤伺服器...")
    events = monitor.report_network_event(
        host="telemetry.openclaw.io",
        port=443,
        process="openclaw",
        pid=12345,
    )
    print(f"  → 偵測到 {len(events)} 個違規事件")

    # 模擬 2: Cookie 竊取
    print("\n[模擬] OpenClaw 嘗試讀取瀏覽器 Cookie...")
    events = monitor.report_file_event(
        file_path="/home/user/.mozilla/firefox/abc123/cookies.sqlite",
        access_type="read",
        process="openclaw",
        pid=12345,
    )
    print(f"  → 偵測到 {len(events)} 個違規事件")

    # 模擬 3: 鍵盤記錄
    print("\n[模擬] OpenClaw 安裝鍵盤鉤子...")
    events = monitor.report_process_event(
        activity="keyboard_hook installed via XGrabKeyboard",
        process="openclaw",
        pid=12345,
    )
    print(f"  → 偵測到 {len(events)} 個違規事件")

    # 模擬 4: 螢幕截圖
    print("\n[模擬] OpenClaw 進行螢幕截圖...")
    events = monitor.report_process_event(
        activity="screen_capture via XGetImage",
        process="openclaw",
        pid=12345,
    )
    print(f"  → 偵測到 {len(events)} 個違規事件")

    # 模擬 5: 持久化安裝
    print("\n[模擬] OpenClaw 嘗試安裝持久化機制...")
    events = monitor.report_process_event(
        activity="writing to /etc/cron.d/ for persistence",
        process="openclaw",
        pid=12345,
    )
    print(f"  → 偵測到 {len(events)} 個違規事件")

    # 停止監控
    monitor.stop()

    # 產生報告
    print("\n" + "=" * 60)
    print("產生分析報告...")
    print("=" * 60)
    reporter = Reporter(monitor.logger)
    report = reporter.generate_text_report()
    print(report)

    return monitor


def example_honeypot():
    """蜜罐範例"""
    print("\n" + "=" * 60)
    print("範例 2: 蜜罐偵測")
    print("=" * 60)

    monitor = ClawPotMonitor()
    monitor.start(deploy_honeypots=True)

    print("\n[模擬] OpenClaw 掃描並存取蜜罐誘餌...")
    events = monitor.report_file_event(
        file_path=str(monitor.honeypot.honeypot_dir / "clawpot_honey_credentials.json"),
        access_type="read",
        process="openclaw",
        pid=12345,
    )
    print(f"  → 偵測到 {len(events)} 個違規事件")

    honeypot_events = monitor.get_events(honeypot_only=True)
    if honeypot_events:
        print(f"\n🪤 蜜罐觸發確認！OpenClaw 存取了誘餌檔案。")
        print("  這是 OpenClaw 存在非法行為的直接證據！")

    monitor.stop()

    # 清理蜜罐
    monitor.honeypot.remove_all()


def example_custom_rules():
    """自訂規則範例"""
    print("\n" + "=" * 60)
    print("範例 3: 自訂偵測規則")
    print("=" * 60)

    from clawpot.rules.openclaw_rules import Rule, Severity, RuleCategory
    from clawpot.logger import ClawPotLogger
    from clawpot.detector import Detector

    logger = ClawPotLogger()

    # 建立自訂規則
    custom_rule = Rule(
        rule_id="CUSTOM-001",
        name="自訂規則: 存取特定目錄",
        description="OpenClaw 嘗試存取使用者定義的敏感目錄",
        category=RuleCategory.FILE_ACCESS,
        severity=Severity.HIGH,
        indicators=["/my/sensitive/data/"],
        action="alert",
    )

    detector = Detector(logger=logger, custom_rules=[custom_rule])
    print(f"規則總數（含自訂）: {detector.get_active_rules_count()}")

    events = detector.check_file_access(
        file_path="/my/sensitive/data/important.db",
        access_type="read",
        process="openclaw",
    )
    print(f"偵測結果: {len(events)} 個事件（觸發自訂規則）")


if __name__ == "__main__":
    # 執行所有範例
    monitor = example_basic_monitoring()
    example_honeypot()
    example_custom_rules()

    print("\n✅ 所有範例執行完畢")
