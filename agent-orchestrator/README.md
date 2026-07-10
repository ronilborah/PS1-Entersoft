# Obsidia Agent Orchestrator

LangGraph ReAct service that coordinates the Obsidia reconnaissance pipeline:
Scout → Mapper → Analyst → Prober → Striker. Each downstream agent is called over
HTTP and receives the accumulated context from prior stages.

## Setup

```bash
cd agent-orchestrator
cp .env.example .env
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The Scout and Prober services are expected on ports 8001 and 8004. If Mapper,
Analyst, or Striker are unavailable, their tool result is recorded as skipped and
the orchestration continues.

## Example

```bash
curl -X POST http://localhost:8000/agents/agent-orchestrator/tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "Run the authorized reconnaissance pipeline and summarize the security posture.",
    "target": "http://demo.testfire.net/",
    "context": {}
  }'
```

Health information, including configured downstream URLs, is available at
`GET http://localhost:8000/health`.
