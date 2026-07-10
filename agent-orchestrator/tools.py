"""HTTP tool wrappers for the specialist recon agents."""

import json
import logging
import os
from typing import Any

import requests
from dotenv import load_dotenv
from langchain_core.tools import tool

load_dotenv()
TIMEOUT_SECONDS = 300
logger = logging.getLogger(__name__)


def _skipped(agent_id: str, reason: str) -> str:
    """Log an unavailable downstream stage and return its standard tool result."""
    logger.warning("Skipping %s: %s", agent_id, reason)
    return json.dumps({"error": reason, "agent": agent_id, "skipped": True})


def _call_agent(agent_id: str, base_url: str, target: str, intent: str, context: dict) -> str:
    """Call one specialist and return only its structured response payload."""
    try:
        response = requests.post(
            f"{base_url.rstrip('/')}/agents/{agent_id}/tasks",
            json={"prompt": intent, "target": target, "context": context},
            timeout=TIMEOUT_SECONDS,
        )
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


@tool
def call_scout(target: str, intent: str, context: dict = {}) -> str:
    """Call the Scout agent to fingerprint a target: tech stack, WAF, TLS, open ports."""
    return _call_agent("agent-scout", os.getenv("SCOUT_URL", "http://localhost:8001"), target, intent, context)


@tool
def call_mapper(target: str, intent: str, context: dict = {}) -> str:
    """Call the Mapper agent to enumerate the target's routes, APIs, parameters, and attack surface."""
    return _call_agent("agent-mapper", os.getenv("MAPPER_URL", "http://localhost:8002"), target, intent, context)


@tool
def call_analyst(target: str, intent: str, context: dict = {}) -> str:
    """Call the Analyst agent to prioritize and assess potential security findings."""
    return _call_agent("agent-analyst", os.getenv("ANALYST_URL", "http://localhost:8003"), target, intent, context)


@tool
def call_prober(target: str, intent: str, context: dict = {}) -> str:
    """Call the Prober agent to safely validate promising findings and collect evidence."""
    return _call_agent("agent-prober", os.getenv("PROBER_URL", "http://localhost:8004"), target, intent, context)


@tool
def call_striker(target: str, intent: str, context: dict = {}) -> str:
    """Call the Striker agent to perform the final authorized exploitation or impact assessment stage."""
    return _call_agent("agent-striker", os.getenv("STRIKER_URL", "http://localhost:8005"), target, intent, context)


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
