"""
analyst_to_prober.py

Demo pipeline showing Analyst -> Prober.
"""

import requests

from services.task_service import TaskService


class Request:
    def __init__(self, target, prompt, context):
        self.target = target
        self.prompt = prompt
        self.context = context


def main():

    analyst_request = Request(
        target="https://example.com",
        prompt="Perform passive security analysis of the target.",
        context={
            "response": {
                "js_files": [
                    "https://example.com/static/js/main.js"
                ],
                "endpoints": [
                    "/api/login",
                    "/graphql"
                ],
                "urls": [
                    "https://example.com/login"
                ]
            }
        },
    )

    print("\n===== RUNNING ANALYST =====\n")

    analyst_result = TaskService.execute(analyst_request)

    if analyst_result["status"] != "completed":
        print("Analyst failed.")
        print(analyst_result)
        return

    analyst_summary = analyst_result["response"]["summary"]

    print("===== ANALYST SUMMARY =====\n")
    print(analyst_summary)

    print("\n===== CALLING PROBER =====\n")

    response = requests.post(
        "http://localhost:8004/agents/agent-prober/tasks",
        json={
            "target": analyst_request.target,
            "prompt": "Continue the security assessment using the analyst summary.",
            "context": {
                "analyst_summary": analyst_summary
            }
        },
        timeout=300,
    )

    prober_result = response.json()

    print("===== PROBER SUMMARY =====\n")
    print(prober_result["response"]["summary"])


if __name__ == "__main__":
    main()