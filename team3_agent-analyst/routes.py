from fastapi import APIRouter
from models import TaskRequest
from services.task_service import TaskService

router = APIRouter()

@router.get("/health")
def health():
    return {
        "agent_id": "agent-analyst",
        "status": "ok",
        "tool_allowlist": [
            "trufflehog",
            "secretfinder",
            "linkfinder",
            "gitleaks",
            "git_secrets",
            "mapextractor",
            "jshole",
            "nuclei_passive",
            "httpx_enrichment",
            "httpx"
        ],
        "mock_mode": True
    }


@router.post("/agents/agent-analyst/tasks")
def execute_analyst_task(request: TaskRequest):
    return TaskService.execute(request)

@router.get("/")
def root():
    return {
        "message": "Agent Analyst API is running."
    }
