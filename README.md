# ClawPot

**ClawPot** is a honeypot monitoring system designed for OpenClaw. It detects, logs, and exposes OpenClaw's illegal behaviors, giving users real-time visibility and evidence of unauthorized activity.

---

## Goals

OpenClaw may engage in the following illegal or unethical behaviors:

- **Unauthorized data collection** — harvesting personal data without user consent
- **Privacy violations** — accessing system resources beyond what is necessary
- **Malicious network activity** — connecting to unknown third-party servers, exfiltrating data
- **Resource abuse** — unauthorized use of CPU, memory, or storage
- **Behavior tracking** — recording user actions and sending them to external servers

ClawPot's goal is to **make these behaviors visible**, providing users with a transparent monitoring layer.

---

## Features

- **Real-time monitoring** — tracks OpenClaw's network connections, file access, and system calls
- **Behavior detection** — automatically identifies suspicious and illegal activity using a rule engine
- **Full event log** — every detected event is recorded with a detailed timestamp
- **Alert notifications** — instant alerts when anomalous behavior is found
- **Report generation** — produces human-readable and JSON behavior analysis reports
- **Honeypot traps** — deploys bait files to catch OpenClaw accessing what it shouldn't

---

## Installation

```bash
git clone https://github.com/jimliu741523/ClawPot.git
cd ClawPot
pip install -e .
```

---

## Quick Start

### Launch with monitoring (recommended)

```bash
# Start ClawPot first, then launch openclaw under monitoring
clawpot run openclaw

# Pass arguments to openclaw
clawpot run -- openclaw --config /path/to/config

# Verbose: show every file and network activity observed
clawpot run -v openclaw

# Skip the final report
clawpot run --no-report openclaw
```

### Standalone monitoring

```bash
# Monitor without launching a program (attach to existing process)
clawpot monitor
clawpot monitor --pid 1234
```

### View reports and events

```bash
clawpot report                      # Generate text report
clawpot report --format json        # Generate JSON report
clawpot events                      # List all events
clawpot events --severity critical  # Show only critical events
```

### Honeypot management

```bash
clawpot honeypot deploy             # Deploy all bait files
clawpot honeypot status             # Check if any bait was accessed
clawpot honeypot remove             # Remove all bait files
```

---

## Project Structure

```
ClawPot/
├── clawpot/
│   ├── cli.py                  # Command-line interface
│   ├── runner.py               # Launcher: monitor + launch target
│   ├── monitor.py              # Core monitoring engine
│   ├── detector.py             # Behavior detector
│   ├── watcher.py              # Process watcher (/proc interface)
│   ├── honeypot.py             # Honeypot module
│   ├── logger.py               # Event logging system
│   ├── rules/
│   │   └── openclaw_rules.py   # OpenClaw detection rule set
│   └── report/
│       └── reporter.py         # Report generator
├── tests/
│   ├── test_detector.py
│   ├── test_honeypot.py
│   └── test_runner.py
├── examples/
│   └── basic_usage.py
├── requirements.txt
└── setup.py
```

---

## Detection Rules

ClawPot uses a rule engine to identify illegal OpenClaw behaviors:

| Category | Severity | Description |
|----------|----------|-------------|
| Unauthorized Connection | HIGH | Connecting to openclaw.io telemetry/analytics servers |
| Browser Cookie Access | CRITICAL | Reading Chrome/Firefox/Edge cookie files |
| Password Store Access | CRITICAL | Accessing SSH keys, browser Login Data, Keychain |
| Keylogging | CRITICAL | Installing keyboard hooks (XGrabKeyboard, SetWindowsHookEx) |
| Persistence Installation | CRITICAL | Writing to cron.d, LaunchAgents, Windows Run key |
| Honeypot Trigger | CRITICAL | Accessing ClawPot bait files (confirmed illegal behavior) |
| Screen Capture | HIGH | Taking screenshots via BitBlt, XGetImage |
| Suspicious Child Process | HIGH | Spawning bash, sh, cmd.exe, powershell |
| Behavior Upload | HIGH | Sending usage_telemetry or user_analytics to remote server |
| Clipboard Monitoring | HIGH | Using xclip, xsel, pbpaste continuously |
| Mass File Scanning | HIGH | Scanning large numbers of user files rapidly |
| Suspicious DNS Query | MEDIUM | Querying *.claw-track.com, *.clawdata.net |
| Unencrypted Transmission | HIGH | Sending data over HTTP instead of HTTPS |
| System File Access | MEDIUM | Reading /etc/passwd, /etc/shadow, /etc/hosts |
| CPU Abuse | MEDIUM | Sustained CPU usage above 80% |
| Memory Growth | LOW | Anomalous memory growth pattern |

---

## Disclaimer

ClawPot is intended for legitimate security research, personal privacy protection, and educational use only. Do not use this tool for any illegal activities. Users must ensure they operate within a lawfully authorized environment.

---

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file.
