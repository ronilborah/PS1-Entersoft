"""FastAPI service for the Obsidia agent orchestrator."""

import json
import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent import run_orchestrator
from tools import downstream_agents

load_dotenv()
AGENT_ID = "agent-orchestrator"

app = FastAPI(title="Obsidia Agent Orchestrator", version="1.0.0")


class TaskRequest(BaseModel):
    prompt: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    context: dict = Field(default_factory=dict)


class TaskResponse(BaseModel):
    agent_id: str
    status: str
    response: dict


@app.get("/health")
def health() -> dict:
    return {
        "agent_id": AGENT_ID,
        "status": "ok",
        "model": os.getenv("OLLAMA_MODEL", "gpt-oss:20b"),
        "downstream_agents": downstream_agents(),
    }


@app.post("/agents/{agent_id}/tasks", response_model=TaskResponse)
async def run_task(agent_id: str, request: TaskRequest) -> TaskResponse:
    if agent_id != AGENT_ID:
        raise HTTPException(status_code=404, detail=f"unknown agent_id '{agent_id}'")

    try:
        prompt = request.prompt
        if request.context:
            prompt += "\n\nInitial caller context:\n" + json.dumps(request.context)
        result = await run_orchestrator(prompt=prompt, target=request.target)
        return TaskResponse(agent_id=AGENT_ID, status="completed", response=result)
    except Exception as exc:
        return TaskResponse(agent_id=AGENT_ID, status="failed", response={"error": str(exc)})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
