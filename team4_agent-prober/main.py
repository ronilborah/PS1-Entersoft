"""main.py

agent-prober — Team 4 ReconAgent specialist (F4 Active Scan, safe tier).

Run:
    uvicorn main:app --port 8004 --reload

Env vars:
    TOOL_MOCK_MODE=true|false      (default: true)
    TOOL_TIMEOUT_SECONDS=300       (per-tool subprocess timeout)
    OLLAMA_BASE_URL=http://localhost:11434/v1
    OLLAMA_MODEL=qwen2.5:7b
    USE_REACT_AGENT=true|false     (default: true — set false to fall back to
                                    keyword planner if Ollama is unreachable)
"""

from __future__ import annotations

import logging
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

from fastapi import FastAPI, HTTPException

from models import HealthResponse, TaskRequest, TaskResponse, TaskResponseBody
from tools import MOCK_MODE, PROBER_ALLOWLIST, get_tool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("agent-prober")

AGENT_ID = "agent-prober"
USE_REACT = os.environ.get("USE_REACT_AGENT", "true").lower() == "true"

app = FastAPI(title="ReconAgent — agent-prober", version="2.0.0")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        agent_id=AGENT_ID,
        status="ok",
        mock_mode=MOCK_MODE,
        tool_allowlist=PROBER_ALLOWLIST,
    )


@app.post("/agents/{agent_id}/tasks", response_model=TaskResponse)
def run_task(agent_id: str, request: TaskRequest) -> TaskResponse:
    if agent_id != AGENT_ID:
        raise HTTPException(status_code=404, detail=f"Unknown agent_id '{agent_id}', expected '{AGENT_ID}'")

    if not request.target:
        return TaskResponse(agent_id=AGENT_ID, status="failed", response={}, error="target is required")

    try:
        if USE_REACT:
            # --- AGENT PATH: LLM-driven ReAct loop ---
            # The LLM reads the prompt and tool outputs and decides what to run.
            from agent import run_react_agent
            result = run_react_agent(request.prompt, request.target, request.context or {})
            return TaskResponse(
                agent_id=AGENT_ID,
                status=result["status"],
                response=result["response"] if result["status"] == "completed"
                         else TaskResponseBody(summary="", findings=[]),
                error=result.get("error"),
            )

        else:
            # --- AUTOMATION FALLBACK: keyword planner (old behaviour) ---
            # Used when Ollama is unreachable. Kept so the service never
            # goes completely dark. Set USE_REACT_AGENT=false to activate.
            from planner import select_tools
            tool_keys = select_tools(request.prompt, request.context)
            logger.info("(fallback) selected tools=%s for target=%s", tool_keys, request.target)

            findings, signal_candidates, tool_errors = [], set(), []
            for tool_key in tool_keys:
                result = get_tool(tool_key).run(request.target, request.context)
                for f in result.get("findings", []):
                    findings.append({**f, "source_tool": tool_key})
                signal_candidates.update(result.get("signal_candidates", []))
                tool_errors.extend(result.get("errors", []))

            summary = (
                f"[FALLBACK MODE — Ollama unreachable] "
                f"Ran {len(tool_keys)} tool(s) ({', '.join(tool_keys)}) against {request.target}. "
                f"{len(findings)} finding(s), {len(signal_candidates)} distinct signal(s)."
            )
            return TaskResponse(
                agent_id=AGENT_ID,
                status="completed",
                response=TaskResponseBody(
                    summary=summary,
                    findings=[{
                        "signal_candidates": sorted(signal_candidates),
                        "tools_used": tool_keys,
                        "tool_errors": tool_errors,
                        "details": findings,
                    }],
                ),
            )

    except PermissionError as exc:
        return TaskResponse(agent_id=AGENT_ID, status="failed", response={}, error=str(exc))
    except Exception as exc:
        logger.exception("agent-prober task failed")
        return TaskResponse(agent_id=AGENT_ID, status="failed", response={}, error=str(exc))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8004"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
