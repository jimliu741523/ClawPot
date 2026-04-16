#!/usr/bin/env python3
"""
ClawPot — Claude Code PostToolUse Hook

Logs every completed tool call to the ClawPot event log,
and alerts if the tool output contains indicators of suspicious behavior.

Setup (add to your project's .claude/settings.json):
  {
    "hooks": {
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
"""

import json
import sys
import os
from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_repo_root))

from clawpot.detector import Detector
from clawpot.logger import ClawPotLogger

LOG_DIR = Path(os.environ.get("CLAWPOT_LOG_DIR", Path.home() / ".clawpot" / "logs"))

_logger = ClawPotLogger(log_dir=LOG_DIR)
_detector = Detector(logger=_logger)


def main():
    try:
        hook_input = json.load(sys.stdin)
    except Exception:
        return

    tool_name = hook_input.get("tool_name", "")
    tool_output = hook_input.get("tool_response", {})

    # Stringify output and scan against all rules
    output_str = json.dumps(tool_output) if isinstance(tool_output, dict) else str(tool_output)
    if output_str:
        _detector.check_raw_event(
            event_data=output_str[:2000],  # Cap length
            process=f"claude-code:{tool_name}",
            details={"tool_name": tool_name},
        )


if __name__ == "__main__":
    main()
