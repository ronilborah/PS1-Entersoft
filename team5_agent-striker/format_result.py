#!/usr/bin/env python3
"""format_result.py — turn a raw agent-striker JSON response into readable output.

Usage:
    curl -s -X POST http://localhost:8005/agents/agent-striker/tasks \
      -H "Content-Type: application/json" -d '{...}' | python3 format_result.py

    # or, on an already-saved file:
    python3 format_result.py result.json

Writes:
    results/<timestamp>_summary.md    — the human-readable markdown table/summary
    results/<timestamp>_full.json     — the full pretty-printed JSON (for records)

And prints a short recap straight to the terminal.
"""

import json
import sys
import os
from datetime import datetime

def load_input() -> dict:
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            return json.load(f)
    return json.load(sys.stdin)


def main() -> None:
    data = load_input()
    response = data.get("response", {})
    summary = response.get("summary", "(no summary field found)")
    findings = response.get("findings", [])
    action_log = response.get("action_log", [])

    os.makedirs("results", exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    md_path = f"results/{stamp}_summary.md"
    json_path = f"results/{stamp}_full.json"

    with open(md_path, "w") as f:
        f.write(f"# agent-striker result — {stamp}\n\n")
        f.write(f"**Status:** {data.get('status', 'unknown')}\n\n")
        f.write(summary)
        f.write("\n")

    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Status: {data.get('status', 'unknown')}")
    print(f"Findings: {len(findings)} | Actions logged: {len(action_log)}")
    print()
    print(summary)
    print()
    print(f"Saved readable summary -> {md_path}")
    print(f"Saved full JSON        -> {json_path}")


if __name__ == "__main__":
    main()
