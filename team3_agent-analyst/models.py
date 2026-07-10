from typing import Any, Dict, List

from pydantic import BaseModel, Field


# ---------- Request Models ----------

class TaskRequest(BaseModel):
    prompt: str = Field(
        ...,
        description="The task the agent should perform."
    )
    target: str = Field(..., description="Target URL.")
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional data for the task."
    )


# ---------- Response Models ----------

class Finding(BaseModel):
    tool: str
    type: str = ""
    severity: str
    title: str
    description: str
    evidence: str
    location: str = ""

class TaskResponse(BaseModel):
    summary: str
    findings: List[Finding] = Field(default_factory=list)


class APIResponse(BaseModel):
    status: str
    response: TaskResponse
