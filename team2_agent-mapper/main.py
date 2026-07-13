"""
main.py — Mapper Agent (Team 2)
FastAPI service on port 8002.
Accepts a natural-language prompt, runs surface enumeration tools,
returns structured JSON findings.
"""

import logging
from typing import Any, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from agent import run_react_agent, MAPPER_TOOLS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent-mapper")

AGENT_ID = "agent-mapper"
PORT     = 8002

ALLOWED_TOOLS = {
    "httpx", "naabu", "katana", "gau", "waybackurls",
    "dirsearch", "jsluice", "nirjas",
    "source_maps_downloader", "nmap_service",
}

app = FastAPI(title="Agent Mapper", version="2.0.0")


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class TaskRequest(BaseModel):
    prompt:  str
    target:  str
    context: Optional[dict] = {}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Returns agent status and tool allowlist."""
    return {
        "agent_id":       AGENT_ID,
        "status":         "ok",
        "port":           PORT,
        "allowed_tools":  sorted(ALLOWED_TOOLS),
        "upstream":       "agent-scout (optional)",
        "downstream":     "agent-analyst",
    }


@app.post("/agents/agent-mapper/tasks")
def run_task(request: TaskRequest):
    """
    Main endpoint. Accepts a prompt + target, runs the LangGraph
    ReAct agent, returns structured findings.
    """
    logger.info("Task received | target=%s | prompt=%s", request.target, request.prompt[:80])

    try:
        result = run_react_agent(
            prompt=request.prompt,
            target=request.target,
            context=request.context or {},
        )
        logger.info("Task complete | status=%s", result.get("status"))
        return result

    except Exception as e:
        logger.exception("Task failed")
        return {
            "agent_id": AGENT_ID,
            "status":   "failed",
            "response": {"error": str(e)},
        }
