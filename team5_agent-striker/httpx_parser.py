"""parsers/httpx_parser.py — parse httpx JSONL output into structured signals."""

import json


def parse_httpx(raw_output: str, target: str) -> dict:
    """Parse httpx output and return signal candidates."""
    result = {
        "tool_name": "httpx",
        "family_id": "F1",
        "target": target,
        "signal_candidates": [],
        "signal_confidence": {},
        "semantic_summary": "",
        "errors": [],
    }
    if not raw_output or not raw_output.strip():
        result["errors"].append("empty input")
        return result
    try:
        data = json.loads(raw_output.strip().splitlines()[0])
    except (json.JSONDecodeError, IndexError):
        result["errors"].append("could not parse httpx JSON")
        return result

    techs = data.get("technologies") or data.get("tech") or []
    if techs:
        result["signal_candidates"].append("tech_stack_detected")
        result["signal_confidence"]["tech_stack_detected"] = 0.9

    server = data.get("server") or ""
    if server and "/" in server:
        result["signal_candidates"].append("server_version_disclosed")
        result["signal_confidence"]["server_version_disclosed"] = 0.85

    result["semantic_summary"] = (
        f"httpx: {data.get('status_code', '?')} on {target}; "
        f"tech={techs}; server={server}"
    )
    return result
