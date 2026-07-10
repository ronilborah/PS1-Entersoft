"""LangGraph ReAct orchestrator for the Obsidia specialist-agent pipeline."""

import json
import os
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from tools import PIPELINE_AGENTS, TOOLS, TOOL_TO_AGENT

load_dotenv()

_llm = ChatOpenAI(
    model=os.getenv("OLLAMA_MODEL", "gpt-oss:20b"),
    base_url=os.getenv("OLLAMA_BASE_URL", "https://ollama.com/v1"),
    api_key=os.getenv("OLLAMA_API_KEY", "ollama"),
    temperature=0,
)

SYSTEM_PROMPT = """You are the Obsidia recon-pipeline orchestrator. You coordinate five specialist
agents in this order: Scout → Mapper → Analyst → Prober → Striker. Call agents in
logical order based on what each returns. For every downstream call after the first,
you MUST pass the previous agent's complete JSON output in that tool call's `context`
argument, accumulating useful findings from earlier stages. If an agent returns JSON
with `skipped: true`, record that it was unavailable and continue; do not abort.

Run every relevant pipeline stage, but never call a specialist agent more than once in
a run. Once all relevant stages are complete, write a concise executive summary from
all available findings. Do not reveal your chain of thought or internal tool trace.
"""


def _structured_result(value: Any) -> dict[str, Any]:
    """Normalize tool output into the public summary/findings shape."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            value = {"summary": value, "findings": []}
    if not isinstance(value, dict):
        value = {"summary": str(value), "findings": []}
    return {
        "summary": str(value.get("summary", value.get("error", "No summary returned."))),
        "findings": value.get("findings", []) if isinstance(value.get("findings", []), list) else [],
    }


async def run_orchestrator(prompt: str, target: str) -> dict:
    """Run the ReAct graph and return a summary plus sanitized pipeline results."""
    graph = create_react_agent(
        _llm,
        tools=TOOLS,
        prompt=SYSTEM_PROMPT,
    )
    result = await graph.ainvoke(
        {"messages": [HumanMessage(content=f"Target: {target}\nObjective: {prompt}")]},
        config={"recursion_limit": 30},
    )

    pipeline_results: dict[str, dict[str, Any]] = {}
    for message in result.get("messages", []):
        name = getattr(message, "name", None)
        if name in TOOL_TO_AGENT:
            pipeline_results[TOOL_TO_AGENT[name]] = _structured_result(getattr(message, "content", ""))

    for agent in PIPELINE_AGENTS:
        pipeline_results.setdefault(agent, {"summary": "Not invoked for this run.", "findings": []})

    final_content = "Orchestration completed; see pipeline results for available findings."
    for message in reversed(result.get("messages", [])):
        if getattr(message, "type", "") == "ai" and getattr(message, "content", None):
            final_content = str(message.content)
            break

    return {"summary": final_content, "pipeline_results": pipeline_results}
