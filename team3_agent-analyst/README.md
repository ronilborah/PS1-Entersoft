# Analyst Agent — Team 3

`agent-analyst` is the passive analysis stage of the Obsidia pipeline. It consumes
Mapper context, scans the discovered web assets for secrets and client-side
exposure, normalizes all results into one finding schema, deduplicates them, and
produces a concise handoff summary for Prober.

## Responsibilities

The request path is:

```text
main.py → routes.py → TaskService.execute()
         → parse_context()
         → select_next_tool() up to 8 times
         → run_tool()
         → aggregate() → summarize_findings()
```

`services/selector.py` asks an Ollama-compatible model to choose one tool at a
time. It rejects unsupported requests, validates the allowlist, prevents repeat
execution, and falls back to keyword rules when the model is unavailable.
`services/runner.py` chooses mock or real implementations and builds the scan
surface from Mapper's `js_files`, `urls`, `endpoints`, and `routes` fields. If no
surface is supplied, it can scrape the target homepage for static script tags.

## Tool allowlist

| Tool | Purpose |
| --- | --- |
| `httpx` | Confirm the target is reachable. |
| `httpx_enrichment` | Collect HTTP metadata, headers, and redirects. |
| `trufflehog` | Search content for leaked secrets. |
| `secretfinder` | Search JavaScript for API keys, tokens, and passwords. |
| `linkfinder` | Extract hidden endpoints and routes from JavaScript. |
| `gitleaks` | Detect secret patterns in content or repositories. |
| `git_secrets` | Check for accidentally committed credentials. |
| `mapextractor` | Detect exposed JavaScript source maps. |
| `jshole` | Detect vulnerable or outdated JavaScript libraries. |
| `nuclei_passive` | Run passive templates for exposed panels and configuration issues. |

Tools that require JavaScript (`secretfinder`, `linkfinder`, `jshole`, and
`mapextractor`) are skipped when Mapper provides no JavaScript and the homepage
contains no static script tags. Secret scanners that can work on generic text
fall back to the target itself.

## Finding schema

Every finding is normalized to the following shape:

```json
{
  "tool": "SecretFinder",
  "type": "Secret",
  "severity": "High",
  "title": "Potential secret",
  "description": "Why this matters",
  "evidence": "REDACTED",
  "location": "https://example.test/assets/app.js"
}
```

The service deduplicates on `(tool, title, location)`. An empty finding list is a
successful passive run, not proof that the target is safe. The summary is an
LLM-generated handoff capped by the summarizer prompt at 250 words, with a
deterministic fallback if summarization is unavailable.

## API and setup

```bash
cd team3_agent-analyst
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PORT=8003 TOOL_MOCK_MODE=true uvicorn main:app --reload --port 8003
```

Health:

```bash
curl http://localhost:8003/health
```

Task with Mapper-style context:

```bash
curl -X POST http://localhost:8003/agents/agent-analyst/tasks \
  -H 'Content-Type: application/json' \
  -d '{
    "prompt": "Perform passive analysis of JavaScript, APIs, and exposed configuration.",
    "target": "https://example.test",
    "context": {
      "js_files": ["https://example.test/static/app.js"],
      "endpoints": ["/api/login", "/graphql"],
      "urls": ["https://example.test/login"]
    }
  }'
```

The task response is shaped as:

```json
{
  "agent_id": "agent-analyst",
  "status": "completed",
  "response": {
    "summary": "...",
    "findings": []
  }
}
```

The included `analyst_to_prober.py` is a standalone integration demonstration;
the orchestrator normally performs the handoff.

## Configuration

The service loads `.env` if present. Important variables are:

| Variable | Default/meaning |
| --- | --- |
| `PORT` | `8003` when run as a script. |
| `TOOL_MOCK_MODE` | The runner defaults to `false`; set `true` for deterministic local development. |
| `OLLAMA_BASE_URL` | `https://ollama.com/v1` in selector/summarizer. |
| `OLLAMA_MODEL` | Used for tool planning and summary generation. |
| `OLLAMA_API_KEY` | Credential for the configured OpenAI-compatible endpoint. |
| `EXTERNAL_TOOLS_DIR` | Directory prepended to `PATH` for real helper scripts. |
| `NUCLEI_TEMPLATES_DIR` | Nuclei template directory for passive scans. |
| `HTTPX_BINARY` | Path to the ProjectDiscovery httpx binary. |

The health route currently returns `mock_mode: true` as a literal. Use the
runner's `TOOL_MOCK_MODE` value, logs, and the actual tool behavior as the
authoritative execution-mode indicators until that endpoint is corrected.

## Mock versus real mode

Mock implementations live in `tools/mock_tools.py` and provide normalized,
redacted sample findings. Real implementations live in `tools/wrappers.py` and
return an empty list when a binary is missing or fails, allowing the rest of the
analysis to continue. Real mode needs the external tools, scripts, and Nuclei
templates installed locally; it also causes network requests to the target.

Use only with explicit authorization. Passive analysis may still download target
content and invoke scanners, so mock mode is the safest default for development.
