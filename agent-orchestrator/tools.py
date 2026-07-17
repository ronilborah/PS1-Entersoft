"""HTTP tool wrappers for the specialist recon agents."""

import json
import logging
import os
import re
import time
from contextvars import ContextVar
from typing import Any

import requests
from dotenv import load_dotenv
from langchain_core.tools import tool

load_dotenv()
TIMEOUT_SECONDS = 400
logger = logging.getLogger(__name__)

TARGET_TRUNCATED_MESSAGE = "Target URL was truncated by LLM. The orchestrator must retry with the full original target URL."
_VALID_TARGET = re.compile(r"^https?://[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}")
_ORIGINAL_TARGET: ContextVar[str | None] = ContextVar("original_target", default=None)


def set_original_target(target: str):
    """Make the request body's target available to tools during one run."""
    return _ORIGINAL_TARGET.set(target)


def reset_original_target(token) -> None:
    """Clear the request target after the graph finishes."""
    _ORIGINAL_TARGET.reset(token)


def _valid_target(target: Any) -> bool:
    if not isinstance(target, str):
        return False
    normalized = target.strip()
    return bool(_VALID_TARGET.match(normalized)) and not normalized.endswith("..") and "..." not in normalized


def _resolved_target(target: str) -> str | None:
    """Use the original request target when the LLM supplied a truncated one."""
    if _valid_target(target):
        return target
    original_target = _ORIGINAL_TARGET.get()
    if _valid_target(original_target):
        logger.warning("Invalid target URL '%s' from LLM; using original request target", target)
        return original_target
    return None


def _invalid_target_result(target: Any) -> str:
    logger.warning("Invalid target URL '%s' from LLM; skipping", target)
    return json.dumps(
        {
            "error": f"Invalid target URL '{target}' from LLM — skipping",
            "skipped": True,
        }
    )


def _target_validation_error(target: Any) -> str | None:
    """Return the standard error for an invalid or truncated target URL."""
    if not _valid_target(target):
        return json.dumps(
            {
                "error": "target_truncated",
                "skipped": True,
                "message": TARGET_TRUNCATED_MESSAGE,
            }
        )
    return None


def _skipped(agent_id: str, reason: str) -> str:
    """Log an unavailable downstream stage and return its standard tool result."""
    logger.warning("Skipping %s: %s", agent_id, reason)
    return json.dumps({"error": reason, "agent": agent_id, "skipped": True})


def _call_agent(agent_id: str, base_url: str, target: str, intent: str, context: str) -> str:
    """Call one specialist and return only its structured response payload."""
    target_error = _target_validation_error(target)
    if target_error:
        return target_error
    try:
        ctx = json.loads(context) if context else {}
    except json.JSONDecodeError:
        ctx = {}
    request_url = f"{base_url.rstrip('/')}/agents/{agent_id}/tasks"
    request_body = {"prompt": intent, "target": target, "context": ctx}
    try:
        response = requests.post(request_url, json=request_body, timeout=TIMEOUT_SECONDS)
    except requests.exceptions.ReadTimeout:
        time.sleep(10)
        try:
            response = requests.post(request_url, json=request_body, timeout=TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            return _skipped(agent_id, str(exc))
    try:
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
    except requests.RequestException as exc:
        return _skipped(agent_id, str(exc))
    except ValueError:
        return _skipped(agent_id, "downstream agent returned invalid JSON")

    if payload.get("status") != "completed":
        reason = payload.get("error") or payload.get("detail") or "downstream agent failed"
        return _skipped(agent_id, str(reason))

    agent_response = payload.get("response")
    if not isinstance(agent_response, dict):
        return _skipped(agent_id, "downstream agent returned no response object")
    return json.dumps(agent_response)


def _truncate_result(result: str, summary_limit: int, findings_limit: int) -> str:
    """Truncate the string returned to the LLM to prevent context overflow."""
    try:
        parsed = json.loads(result)
    except json.JSONDecodeError:
        return result
    if isinstance(parsed, dict):
        if "summary" in parsed and isinstance(parsed["summary"], str):
            parsed["summary"] = parsed["summary"][:summary_limit]
        if "findings" in parsed and isinstance(parsed["findings"], list):
            parsed["findings"] = parsed["findings"][:findings_limit]
    return json.dumps(parsed)


@tool
def call_scout(target: str, intent: str, context: str = "{}") -> str:
    """Call the Scout agent to fingerprint a target: tech stack, WAF, TLS, open ports."""
    requested_target = target
    target = _resolved_target(target)
    if target is None:
        return _invalid_target_result(requested_target)
    result = _call_agent("agent-scout", os.getenv("SCOUT_URL", "http://localhost:8001"), target, intent, context)
    return _truncate_result(result, summary_limit=600, findings_limit=5)


@tool
def call_mapper(target: str, intent: str, context: str = "{}") -> str:
    """Call the Mapper agent to enumerate the target's routes, APIs, parameters, and attack surface."""
    requested_target = target
    target = _resolved_target(target)
    if target is None:
        return _invalid_target_result(requested_target)
    result = _call_agent("agent-mapper", os.getenv("MAPPER_URL", "http://localhost:8002"), target, intent, context)
    return _truncate_result(result, summary_limit=500, findings_limit=3)


@tool
def call_analyst(target: str, intent: str, context: str = "{}") -> str:
    """Call the Analyst agent to prioritize and assess potential security findings."""
    requested_target = target
    target = _resolved_target(target)
    if target is None:
        return _invalid_target_result(requested_target)
    result = _call_agent("agent-analyst", os.getenv("ANALYST_URL", "http://localhost:8003"), target, intent, context)
    return _truncate_result(result, summary_limit=500, findings_limit=3)


@tool
def call_prober(target: str, intent: str, context: str = "{}") -> str:
    """Call the Prober agent to safely validate promising findings and collect evidence."""
    requested_target = target
    target = _resolved_target(target)
    if target is None:
        return _invalid_target_result(requested_target)
    result = _call_agent("agent-prober", os.getenv("PROBER_URL", "http://localhost:8004"), target, intent, context)
    try:
        parsed = json.loads(result)
    except json.JSONDecodeError:
        return result
    if isinstance(parsed, dict):
        parsed["specific_endpoints"] = parsed.get("specific_endpoints", [])
        return _truncate_result(json.dumps(parsed), summary_limit=500, findings_limit=3)
    return result


@tool
def call_striker(
    target: str,
    intent: str,
    context: str = "{}",
    specific_endpoints: list[str] = [],
) -> str:
    """Call the Striker agent to perform the final authorized exploitation or impact assessment stage."""
    requested_target = target
    target = _resolved_target(target)
    if target is None:
        return _invalid_target_result(requested_target)
    try:
        context_payload = json.loads(context) if context else {}
    except json.JSONDecodeError:
        context_payload = {}
    if not isinstance(context_payload, dict):
        context_payload = {}
    context_payload["specific_endpoints"] = specific_endpoints
    result = _call_agent(
        "agent-striker",
        os.getenv("STRIKER_URL", "http://localhost:8005"),
        target,
        intent,
        json.dumps(context_payload),
    )
    return _truncate_result(result, summary_limit=400, findings_limit=3)


# Keep the pipeline registration in this file. Adding a specialist only requires
# its wrapper and one entry here; the graph and health endpoint consume this registry.
AGENT_REGISTRY = (
    ("scout", "agent-scout", "SCOUT_URL", "http://localhost:8001", call_scout),
    ("mapper", "agent-mapper", "MAPPER_URL", "http://localhost:8002", call_mapper),
    ("analyst", "agent-analyst", "ANALYST_URL", "http://localhost:8003", call_analyst),
    ("prober", "agent-prober", "PROBER_URL", "http://localhost:8004", call_prober),
    ("striker", "agent-striker", "STRIKER_URL", "http://localhost:8005", call_striker),
)
PIPELINE_AGENTS = tuple(name for name, *_ in AGENT_REGISTRY)
TOOLS = [tool for *_, tool in AGENT_REGISTRY]
TOOL_TO_AGENT = {tool.name: name for name, *_, tool in AGENT_REGISTRY}


def downstream_agents() -> list[dict[str, str]]:
    """Return the public downstream-agent health metadata from the central registry."""
    return [
        {"agent_id": agent_id, "url": os.getenv(url_env, default_url)}
        for _, agent_id, url_env, default_url, _ in AGENT_REGISTRY
    ]
