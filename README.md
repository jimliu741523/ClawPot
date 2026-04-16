# ClawPot

```
   ██████╗██╗      █████╗ ██╗    ██╗██████╗  ██████╗ ████████╗
  ██╔════╝██║     ██╔══██╗██║    ██║██╔══██╗██╔═══██╗╚══██╔══╝
  ██║     ██║     ███████║██║ █╗ ██║██████╔╝██║   ██║   ██║
  ██║     ██║     ██╔══██║██║███╗██║██╔═══╝ ██║   ██║   ██║
  ╚██████╗███████╗██║  ██║╚███╔███╔╝██║     ╚██████╔╝   ██║
   ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝      ╚═════╝    ╚═╝

         🍯  Catch the claw. Expose the truth.  🍯

      ┌─────────────────────────────────────────────┐
      │  Target: openclaw / claude-code / any app   │
      │                                             │
      │  [ file ]──►                                │
      │  [ net  ]──► Detector ──► ALERT / LOG       │
      │  [ proc ]──►    │                           │
      │                 ▼                           │
      │          🪤 Honeypot Trap                   │
      └─────────────────────────────────────────────┘
```

**ClawPot** is a honeypot monitoring system that watches any target program —
OpenClaw, Claude Code, or any application — and exposes illegal or suspicious
behaviors in real time.

---

## Goals

ClawPot catches programs that engage in:

- **Unauthorized data collection** — harvesting personal data without user consent
- **Privacy violations** — accessing credentials, cookies, SSH keys, or `.env` files
- **Malicious network activity** — connecting to telemetry/tracking servers, exfiltrating data
- **Resource abuse** — unauthorized use of CPU, memory, or storage
- **Behavior tracking** — keylogging, screen capture, clipboard monitoring
- **Persistence installation** — writing to cron.d, LaunchAgents, Windows Run key

---

## Features

- **Works on any program** — not just OpenClaw; monitor Claude Code, Electron apps, or anything
- **Real-time process watching** — tracks file access, network connections, child processes via `/proc`
- **Rule engine** — OpenClaw-specific rules + general suspicious-behavior rules
- **Honeypot traps** — deploys bait files; access = confirmed illegal behavior
- **Full event log** — JSONL format, queryable by severity and category
- **Claude Code hooks** — `PreToolUse` / `PostToolUse` hooks intercept every Claude action

---

## Installation

```bash
git clone https://github.com/jimliu741523/ClawPot.git
cd ClawPot
pip install -e .
```

---

## Usage

### Wrap any program (recommended)

```bash
# Monitor openclaw
clawpot run openclaw

# Monitor claude (Claude Code CLI)
clawpot run claude

# Pass arguments through
clawpot run -- openclaw --config /path/to/config

# Verbose: print every file/network event observed
clawpot run -v claude

# Skip the final report
clawpot run --no-report openclaw
```

### Standalone monitor (attach to running process)

```bash
clawpot monitor --pid 1234
clawpot monitor --process openclaw
```

### Reports and events

```bash
clawpot report                      # Text report
clawpot report --format json        # JSON report
clawpot events                      # All events
clawpot events --severity critical  # Critical only
clawpot events --honeypot-only      # Honeypot triggers only
```

### Honeypots

```bash
clawpot honeypot deploy             # Deploy all bait files
clawpot honeypot status             # Check trigger status
clawpot honeypot remove             # Clean up
```

### Detection rules

```bash
clawpot rules                       # All rules
clawpot rules --category privacy    # Privacy rules only
clawpot rules --severity critical   # Critical rules only
```

---

## Claude Code Integration

ClawPot can intercept every tool call Claude Code makes **before** it executes,
blocking calls that match a critical rule.

### Setup

1. Copy the hook snippet into your project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/ClawPot/hooks/pre_tool_use.py"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/ClawPot/hooks/post_tool_use.py"
          }
        ]
      }
    ]
  }
}
```

2. Replace `/path/to/ClawPot` with where you cloned this repo.

### What the hooks check

| Hook | Checks |
|------|--------|
| `PreToolUse` | File paths in Read/Write/Edit calls, URLs in WebFetch, commands in Bash |
| `PostToolUse` | Tool output scanned against all rules |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAWPOT_BLOCK_SEVERITY` | `critical` | Minimum severity to **block** a tool call |
| `CLAWPOT_LOG_DIR` | `~/.clawpot/logs` | Log directory |

Set `CLAWPOT_BLOCK_SEVERITY=high` to block high-severity calls too.

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
│   │   └── openclaw_rules.py   # OpenClaw + general detection rules
│   └── report/
│       └── reporter.py         # Report generator
├── hooks/
│   ├── pre_tool_use.py         # Claude Code PreToolUse hook
│   ├── post_tool_use.py        # Claude Code PostToolUse hook
│   └── settings_snippet.json  # Ready-to-paste settings block
├── tests/
├── examples/
├── requirements.txt
└── setup.py
```

---

## Detection Rules

### OpenClaw-specific rules (prefix `OC-`)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| OC-NET-001 | HIGH | Connection to openclaw.io telemetry/analytics |
| OC-NET-002 | MEDIUM | Suspicious DNS query to *.claw-track.com |
| OC-NET-003 | HIGH | Unencrypted HTTP data transmission |
| OC-PRIV-001 | CRITICAL | Browser cookie file access |
| OC-PRIV-002 | CRITICAL | Password store / SSH key access |
| OC-PRIV-003 | HIGH | Clipboard monitoring |
| OC-FILE-001 | MEDIUM | System config file access |
| OC-FILE-002 | CRITICAL | Honeypot bait file triggered |
| OC-FILE-003 | HIGH | Mass file scanning |
| OC-TRACK-001 | CRITICAL | Keylogging (XGrabKeyboard, SetWindowsHookEx) |
| OC-TRACK-002 | HIGH | Screen capture (BitBlt, XGetImage) |
| OC-TRACK-003 | HIGH | Behavior analytics upload |
| OC-PROC-001 | HIGH | Suspicious child process (bash, powershell) |
| OC-PROC-002 | CRITICAL | Persistence mechanism installation |

### General rules — any program (prefix `GEN-`)

| Rule ID | Severity | Description |
|---------|----------|-------------|
| GEN-NET-001 | MEDIUM | Connection to ad/tracking networks |
| GEN-NET-002 | HIGH | Unexpected data upload |
| GEN-PRIV-001 | CRITICAL | Browser credential / session token access |
| GEN-PRIV-002 | HIGH | `.env` / secrets file access |
| GEN-FILE-001 | MEDIUM | Sensitive system file access |
| GEN-TRACK-001 | CRITICAL | Keylogging system call |
| GEN-TRACK-002 | HIGH | Screen capture |
| GEN-PROC-001 | HIGH | Shell spawned |
| GEN-HONEY-001 | CRITICAL | Honeypot bait file accessed |

---

## Disclaimer

ClawPot is intended for legitimate security research, personal privacy protection,
and educational use only. Do not use this tool for any illegal activities.
Users must ensure they operate within a lawfully authorized environment.

---

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file.
