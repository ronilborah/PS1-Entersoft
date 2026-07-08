"""
main.py
-------
FastAPI service for Team 1: Scout (F1 Fingerprinting).

Endpoints (per the ReconAgent Intern Assignment contract):
    GET  /health
    POST /agents/{agent_id}/tasks

Run locally:
    uvicorn main:app --reload --port 8001

Env vars (see .env.example):
    TOOL_MOCK_MODE    — true|false (controls mock vs real tool execution)
    OLLAMA_BASE_URL   — Ollama endpoint (default: http://localhost:11434/v1)
    OLLAMA_MODEL      — model name (default: llama3)
"""

import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from agent import run_react_agent        # NEW: LangGraph ReAct agent
from tools import mock_mode

load_dotenv()

AGENT_ID = "agent-scout"
SCOUT_ALLOWLIST = {"httpx", "wafw00f", "whatweb", "shcheck", "testssl", "nmap", "wpscan"}

app = FastAPI(title="ReconAgent - Scout", version="2.0.0")


class TaskRequest(BaseModel):
    prompt: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    context: dict = Field(default_factory=dict)


class TaskResponse(BaseModel):
    agent_id: str
    status: str
    response: dict


@app.get("/health")
def health():
    return {
        "agent_id": AGENT_ID,
        "status": "ok",
        "mock_mode": mock_mode(),
        "tool_allowlist": sorted(SCOUT_ALLOWLIST),
        "ollama_base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        "ollama_model": os.getenv("OLLAMA_MODEL", "llama3"),
    }


@app.post("/agents/{agent_id}/tasks", response_model=TaskResponse)
def run_task(agent_id: str, request: TaskRequest):
    if agent_id != AGENT_ID:
        raise HTTPException(
            status_code=404,
            detail=f"unknown agent_id '{agent_id}'. This service only serves '{AGENT_ID}'.",
        )

    result = run_react_agent(
        prompt=request.prompt,
        target=request.target,
        context=request.context or {},
    )
    return TaskResponse(**result)
