"""main.py — FastAPI entry point for agent-striker (Team 5, port 8005).

Endpoints:
  POST /agents/agent-striker/tasks  — accepts prompt + target + context, returns structured JSON
  GET  /health                      — returns agent status and tool allowlist
"""

import os
import urllib.request
import urllib.error
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

from agent import run_react_agent

load_dotenv()

AGENT_ID = "agent-striker"
VERSION  = "1.0.0"

TOOL_ALLOWLIST = [
    "httpx",
    "sqlmap",
    "xsstrike",
    "dalfox",
    "smuggler",
    "ssrfmap",
    "tplmap",
    "crlfuzzer",
]


def _check_environment() -> None:
    """Print startup warnings for missing or unreachable config."""
    mock_mode = os.getenv("TOOL_MOCK_MODE", "true").lower()
    if mock_mode not in ("true", "false"):
        print(f"[WARN] TOOL_MOCK_MODE={mock_mode!r} is not 'true' or 'false' — defaulting to true")

    api_key = os.getenv("OLLAMA_API_KEY", "")
    if not api_key or api_key in ("ollama", "changeme"):
        print("[WARN] OLLAMA_API_KEY is not set or is a placeholder — Ollama Cloud requests will fail")

    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    try:
        req = urllib.request.Request(
            f"{base_url}/models",
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
        )
        with urllib.request.urlopen(req, timeout=4):
            print(f"[OK]   Ollama endpoint reachable: {base_url}")
    except Exception as exc:
        print(f"[WARN] Ollama endpoint unreachable ({base_url}): {exc}")

    mode_label = "MOCK" if mock_mode == "true" else "REAL"
    print(f"[OK]   agent-striker v{VERSION} starting — tool mode: {mode_label}")


_check_environment()

app = FastAPI(title="agent-striker", version=VERSION)


class TaskRequest(BaseModel):
    prompt: str
    target: str
    context: dict = {}


@app.post("/agents/{agent_id}/tasks")
def run_task(agent_id: str, req: TaskRequest):
    # Deliberately sync (not async): run_react_agent is blocking (LLM round-trips,
    # subprocess calls). A sync def lets FastAPI run it in a background thread so
    # the event loop stays free for other requests (including /health).
    if agent_id != AGENT_ID:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_id}")
    try:
        result = run_react_agent(
            prompt=req.prompt,
            target=req.target,
            context=req.context,
        )
        return result
    except Exception as exc:
        return {
            "agent_id": AGENT_ID,
            "status": "failed",
            "response": {
                "summary": f"Agent error: {str(exc)}",
                "findings": [],
                "hitl_log": [],
                "action_log": [],
            },
        }


@app.get("/health")
async def health():
    return {
        "agent_id": AGENT_ID,
        "status": "ok",
        "version": VERSION,
        "tool_allowlist": TOOL_ALLOWLIST,
        "mock_mode": os.getenv("TOOL_MOCK_MODE", "true").lower() == "true",
    }
