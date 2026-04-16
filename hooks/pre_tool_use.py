#!/usr/bin/env python3
"""
ClawPot — Claude Code PreToolUse Hook

Intercepts every tool call Claude Code makes and checks it against
ClawPot's detection rules before the tool is allowed to execute.

How it works:
  Claude Code runs this script before every tool call.
  The script reads the tool input from stdin as JSON, runs it through
  the ClawPot detector, and writes a JSON response to stdout.

  Response schema:
    {"continue": true}          — allow the tool call
    {"continue": false,
     "reason": "..."}           — block the tool call (Claude sees the reason)

Setup (add to your project's .claude/settings.json):
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
      ]
    }
  }
"""

import json
import sys
import os
from pathlib import Path

# Allow running without installing the package
_repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_repo_root))

from clawpot.detector import Detector
from clawpot.logger import ClawPotLogger
from clawpot.rules.openclaw_rules import Severity

# ── Config ────────────────────────────────────────────────────────────────────
BLOCK_ON_SEVERITY = os.environ.get("CLAWPOT_BLOCK_SEVERITY", "critical")
LOG_DIR = Path(os.environ.get("CLAWPOT_LOG_DIR", Path.home() / ".clawpot" / "logs"))

_logger = ClawPotLogger(log_dir=LOG_DIR)
_detector = Detector(logger=_logger)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_block_threshold = _SEVERITY_ORDER.get(BLOCK_ON_SEVERITY, 3)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    try:
        hook_input = json.load(sys.stdin)
    except Exception:
        _allow()
        return

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    events = _check_tool_call(tool_name, tool_input)

    if not events:
        _allow()
        return

    # Find highest severity event
    worst = max(events, key=lambda e: _SEVERITY_ORDER.get(e.severity, 0))
    worst_level = _SEVERITY_ORDER.get(worst.severity, 0)

    if worst_level >= _block_threshold:
        _block(
            f"[ClawPot] {worst.rule_id} {worst.rule_name} — {worst.description}"
        )
    else:
        # Log but allow
        _allow()


def _check_tool_call(tool_name: str, tool_input: dict):
    """Map Claude Code tool calls to ClawPot detector checks."""
    events = []
    process = f"claude-code:{tool_name}"

    # Read / Write / Edit tools — check file paths
    for key in ("file_path", "path", "notebook_path"):
        path = tool_input.get(key, "")
        if path:
            events += _detector.check_file_access(
                file_path=path,
                access_type=tool_name.lower(),
                process=process,
            )

    # WebFetch / WebSearch — check URLs/queries
    url = tool_input.get("url", "") or tool_input.get("query", "")
    if url:
        host = url.split("/")[2] if "://" in url else url
        events += _detector.check_network_connection(host=host, process=process)

    # Bash tool — check the command string
    command = tool_input.get("command", "")
    if command:
        events += _detector.check_process_activity(
            activity=command,
            process=process,
        )
        # Also scan raw command against all rules
        events += _detector.check_raw_event(
            event_data=command,
            process=process,
        )

    return events


def _allow():
    print(json.dumps({"continue": True}))


def _block(reason: str):
    print(json.dumps({"continue": False, "reason": reason}))


if __name__ == "__main__":
    main()
