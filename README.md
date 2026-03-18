# ClawPot 🪤

**ClawPot** 是一個專為 OpenClaw 設計的蜜罐監控系統，用於偵測、記錄並揭露 OpenClaw 的非法行為，讓使用者能即時觀察並保護自身權益。

---

## 專案目標

OpenClaw 在運作過程中可能存在以下非法或不當行為：

- **未授權資料蒐集**：在未告知使用者的情況下蒐集個人資料
- **隱私侵犯**：存取超出必要範圍的系統資源
- **惡意網路活動**：連線至未知第三方伺服器、資料外洩
- **系統資源濫用**：未授權使用 CPU、記憶體或儲存空間
- **行為追蹤**：追蹤使用者操作紀錄並回傳外部伺服器

ClawPot 的目的是**讓這些行為無所遁形**，提供透明的監控視角給使用者。

---

## 功能特色

- **即時監控**：監控 OpenClaw 的網路連線、檔案存取與系統呼叫
- **行為偵測**：根據規則庫自動識別可疑與非法行為
- **完整日誌**：所有偵測到的事件均有詳細時間戳記錄
- **警報通知**：發現異常行為時即時提醒使用者
- **報告產生**：產生可讀的行為分析報告
- **蜜罐誘捕**：設置誘餌資料，觀察 OpenClaw 是否嘗試存取

---

## 安裝

```bash
git clone https://github.com/jimliu741523/ClawPot.git
cd ClawPot
pip install -r requirements.txt
pip install -e .
```

---

## 快速開始

### 啟動監控

```bash
# 啟動即時監控
clawpot monitor

# 監控並輸出詳細資訊
clawpot monitor --verbose

# 指定監控目標 PID
clawpot monitor --pid <openclaw_pid>
```

### 查看報告

```bash
# 產生行為分析報告
clawpot report

# 查看今日事件
clawpot events --today

# 匯出報告為 JSON
clawpot report --format json --output report.json
```

### 蜜罐設置

```bash
# 部署蜜罐誘餌
clawpot honeypot deploy

# 查看蜜罐觸發紀錄
clawpot honeypot status
```

---

## 專案結構

```
ClawPot/
├── clawpot/
│   ├── __init__.py
│   ├── cli.py              # 命令列介面
│   ├── monitor.py          # 核心監控引擎
│   ├── detector.py         # 非法行為偵測器
│   ├── honeypot.py         # 蜜罐模組
│   ├── logger.py           # 日誌系統
│   ├── rules/
│   │   ├── __init__.py
│   │   └── openclaw_rules.py  # OpenClaw 行為規則庫
│   └── report/
│       ├── __init__.py
│       └── reporter.py     # 報告產生器
├── tests/
│   ├── __init__.py
│   ├── test_detector.py
│   ├── test_honeypot.py
│   └── test_monitor.py
├── examples/
│   └── basic_usage.py
├── requirements.txt
├── setup.py
└── README.md
```

---

## 偵測規則

ClawPot 使用規則引擎來識別 OpenClaw 的非法行為，規則分類如下：

| 類別 | 嚴重程度 | 說明 |
|------|---------|------|
| 未授權網路連線 | 🔴 高 | 連線至未知外部 IP |
| 隱私資料存取 | 🔴 高 | 存取瀏覽器 Cookie、密碼庫等 |
| 系統資源濫用 | 🟡 中 | CPU/記憶體使用超出正常範圍 |
| 可疑檔案操作 | 🟡 中 | 讀取或修改系統關鍵檔案 |
| 行為追蹤 | 🟠 中高 | 記錄使用者操作並回傳 |
| 異常進程活動 | 🟡 中 | 產生不明子進程 |

---

## 免責聲明

ClawPot 僅供合法的安全研究、個人隱私保護及教育用途。請勿將本工具用於任何非法活動。使用者應確保在合法授權的環境下使用本工具。

---

## 授權

本專案採用 [LICENSE](LICENSE) 授權。
