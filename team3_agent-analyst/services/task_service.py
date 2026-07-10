"""
task_service.py — Person B owns this file.

This is the single integration point between your work (Person B)
and Praneet's work (Person A).

Praneet's routes.py calls exactly ONE thing:
    TaskService.execute(request)

And gets back:
    {
        "agent_id": "agent-analyst",
        "status":   "completed",
        "response": {
            "summary":  "...",
            "findings": [...]
        }
    }

Everything else (parser, selector, runner, aggregator) is internal
to this service. Praneet never touches those files.
"""

import logging
import traceback

from services.parser      import parse_context
#from services.selector    import select_tools
from services.runner      import run_tools
from services.aggregator  import aggregate
from services.selector import select_next_tool
from services.runner import run_tool

logger = logging.getLogger("agent-analyst.task_service")

AGENT_ID = "agent-analyst"


class TaskService:

    @staticmethod
    def execute(request) -> dict:
        """
        Main entry point. Accepts the FastAPI request object (or any
        object with .prompt, .target, .context attributes).

        Returns the full API response dict.
        """
        try:
            target = request.target
            logger.info("New task | target=%s | prompt=%s", target, request.prompt[:80])
            

            # Step 1: parse what Mapper sent us
            context_data = parse_context(request.context or {})
            logger.info("Surface from context: %s", context_data)
            '''
            # Step 2: use Ollama (or keyword fallback) to pick tools
            tools = select_tools(request.prompt)
            logger.info("Selected tools: %s", tools)

            # Step 3: run the tools and collect findings
            findings = run_tools(tools, target, context_data)
            '''
            planner_feedback = []
            findings = []
            used_tools = []
            MAX_STEPS = 8
            for step in range(MAX_STEPS):
                 last_tool_findings = []
                 if findings:
                        last_tool = findings[-1].get("tool")
                        last_tool_findings = [
                               f for f in findings
                               if f.get("tool") == last_tool
                               ]
                 planner_findings = (
                               last_tool_findings
                               if len(last_tool_findings) > 20
                               else findings[-20:]
                               )
                 decision = select_next_tool(
                             request.prompt,
                             planner_findings,
                             used_tools,
                             planner_feedback,
                             )
                 if decision.get("unsupported"):
                      logger.info("Planner rejected unsupported request.")
                      return {
                           "agent_id": AGENT_ID,
                           "status": "unsupported",
                           "response": {
                                "summary": "Request is outside the scope of passive security analysis.",
                                "findings": [],
                                },
                                }
                 if decision["finish"]:
                      logger.info(
                           "Planner finished after %d step(s).",
                           step,
                           )
                      break
                 tool = decision["tool"]
                 if decision.get("tool") is None:
                       planner_feedback.append(decision["feedback"])
                       continue
                 logger.info(
                      "Planner selected: %s",
                      tool,
                      )
                 result = run_tool(
                      tool,
                      target,
                      context_data,
                      )
                 findings.extend(result)
                 used_tools.append(tool)

            # Step 4: build summary + structured response
            response_body = aggregate(findings, context_data,)

            return {
                "agent_id": AGENT_ID,
                "status":   "completed",
                "response": response_body,
            }

        except Exception as e:
            logger.error("Task failed: %s\n%s", e, traceback.format_exc())
            return {
                "agent_id": AGENT_ID,
                "status":   "failed",
                "response": {
                    "error":   str(e),
                    "summary": "Task failed due to an internal error.",
                    "findings": [],
                },
            }
