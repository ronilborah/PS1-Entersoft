# agent-striker — Team 5

**Students:** Sai Siddharth Davuluri, Samantula Devendra Supreeth  
**Port:** 8005  
**Agent ID:** `agent-striker`  
**Role:** F4 Active Scan (exploit validation) — the last stage of the Obsidia pipeline

---

## What agent-striker does

agent-striker is a FastAPI + LangGraph ReAct security exploitation agent. It takes findings
from the upstream Prober agent — "this URL might be SQLi injectable" — and actually runs
exploit tools to confirm or disprove them. Because exploit tools can cause real damage, the
agent enforces a **Human-In-The-Loop (HITL) gate**: it must ask for approval before running
any exploit. The AI reasoning framework is **ReAct** (Reason + Act): the LLM sees the task,
picks a tool, reads its output, reasons again, picks the next tool, and continues until it
has enough to write a final answer. Every tool call is logged with an `intent_is_malicious`
flag and a full `action_log` is returned in the response for auditing.

---

## Setup

### Requirements

- Python 3.10+
- An Ollama API key (from [ollama.com/settings/keys](https://ollama.com/settings/keys)) for cloud mode,
  or a local Ollama instance for local mode

### Install dependencies

```bash
pip install -r requirements.txt
# On Kali Linux if you get "externally-managed-environment":
pip install -r requirements.txt --break-system-packages
```

### Configure environment variables

```bash
cp env.example .env
```

Edit `.env` and set these variables:

| Variable | Required | Description |
|---|---|---|
| `TOOL_MOCK_MODE` | Yes | `true` = use mock outputs (no real binaries needed); `false` = run real tools |
| `OLLAMA_BASE_URL` | Yes | Ollama endpoint. `https://ollama.com/v1` for cloud; `http://localhost:11434/v1` for local |
| `OLLAMA_MODEL` | Yes | Model name, e.g. `gpt-oss:20b-cloud` (cloud) or `llama3` (local) |
| `OLLAMA_API_KEY` | Cloud only | API key from ollama.com. Ignored by local Ollama |
| `TOOLS_DIR` | Real mode only | Path where script-based tools are cloned (default `~/tools`) |

---

## Tool status — real mode vs mock-only

This is a macOS development machine. **All 8 tools are mock-only here** — none of the
security binaries are installed. Real-mode execution requires a Kali Linux environment
(see "Installing real tools" below).

| Tool | Mock | Real mode | Notes |
|---|---|---|---|
| `httpx` | ✅ | ❌ MISSING | Needs `httpx-toolkit` binary (Kali: `sudo apt install httpx-toolkit`) |
| `sqlmap` | ✅ | ❌ MISSING | Needs `sqlmap` binary (Kali: `sudo apt install sqlmap`) |
| `xsstrike` | ✅ | ❌ MISSING | Needs `~/tools/XSStrike/xsstrike.py` cloned |
| `dalfox` | ✅ | ❌ MISSING | Needs `dalfox` binary (Go install) |
| `smuggler` | ✅ | ❌ MISSING | Needs `~/tools/smuggler/smuggler.py` cloned |
| `ssrfmap` | ✅ | ❌ MISSING | Needs `~/tools/SSRFmap/ssrfmap.py` cloned |
| `tplmap` | ✅ | ❌ MISSING | Needs `~/tools/SSTImap/sstimap.py` cloned (SSTImap, not tplmap) |
| `crlfuzzer` | ✅ | ❌ MISSING | Needs `crlfuzz` binary (Kali: `sudo apt install crlfuzz`) |

When a real-mode tool is missing, the agent catches the `RuntimeError`, logs a `[WARN]`
to the terminal, adds a `status: "skipped"` entry to `findings[]`, and continues — the
API never crashes on a single tool failure.

---

## How to run

```bash
# Mock mode (default — no binaries needed):
uvicorn main:app --port 8005 --reload

# Real mode (Kali only, all tools must be installed):
# Set TOOL_MOCK_MODE=false in .env, then:
uvicorn main:app --port 8005 --reload
```

On startup the server prints:
- `[OK]` or `[WARN]` for the Ollama endpoint reachability check
- `[WARN]` if `OLLAMA_API_KEY` is missing or a placeholder
- The current tool mode (MOCK or REAL)

---

## API reference

### GET /health

```bash
curl http://localhost:8005/health
```

Response:
```json
{
  "agent_id": "agent-striker",
  "status": "ok",
  "version": "1.0.0",
  "tool_allowlist": ["httpx", "sqlmap", "xsstrike", "dalfox", "smuggler", "ssrfmap", "tplmap", "crlfuzzer"],
  "mock_mode": true
}
```

### POST /agents/agent-striker/tasks

```bash
curl -X POST http://localhost:8005/agents/agent-striker/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Validate the injection points found by Prober. Require HITL before each exploit.",
    "target": "http://testphp.vulnweb.com/",
    "context": {
      "summary": "Prober found injectable param id= on /listproducts.php and reflected XSS on search.php?q=",
      "findings": [
        {"type": "sqli_candidate", "url": "http://testphp.vulnweb.com/listproducts.php?cat=1"},
        {"type": "xss_candidate",  "url": "http://testphp.vulnweb.com/search.php?test=query"}
      ]
    }
  }'
```

Response shape:
```json
{
  "agent_id": "agent-striker",
  "status": "completed",
  "response": {
    "summary": "Confirmed SQLi on /listproducts.php?cat= via UNION technique...",
    "findings": [
      {
        "tool": "sqlmap",
        "target": "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "summary": "Injectable param confirmed: MySQL 8.0, UNION-based",
        "status": "completed"
      },
      {
        "tool": "dalfox",
        "target": "http://testphp.vulnweb.com/search.php?test=query",
        "summary": "SKIPPED: dalfox: not available in this environment — binary missing or incompatible",
        "status": "skipped"
      }
    ],
    "hitl_log": [...],
    "action_log": [...]
  }
}
```

---

## Output files

Every tool run and every final response is saved as structured JSON in the `outputs/` directory
(created automatically next to `main.py`):

```
outputs/
├── httpx_20260707_143201.json          # per-tool result
├── sqlmap_20260707_143215.json
├── final_response_20260707_143230.json # full agent response
```

Each per-tool file has this schema:
```json
{
  "tool": "httpx",
  "target": "http://testphp.vulnweb.com/",
  "raw_output": "...",
  "parsed_findings": [...],
  "timestamp": "2026-07-07T14:32:01Z",
  "mode": "mock"
}
```

You can also pipe the API response through `format_result.py` for a human-readable markdown
summary and full JSON copy in `results/`:

```bash
curl -s -X POST http://localhost:8005/agents/agent-striker/tasks \
  -H "Content-Type: application/json" -d '{...}' | python3 format_result.py
```

---

## Installing real tools (Kali Linux only)

Run these once on your Kali VM, then set `TOOL_MOCK_MODE=false` in `.env`.

### Binary tools

```bash
sudo apt update
sudo apt install -y sqlmap httpx-toolkit crlfuzz golang-go
```

Dalfox (not in Kali repos — install via Go):
```bash
go install github.com/hahwul/dalfox/v2@latest
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
dalfox version
```

### Script-based tools

```bash
mkdir -p ~/tools && cd ~/tools

git clone https://github.com/s0md3v/XSStrike
pip install -r XSStrike/requirements.txt --break-system-packages

git clone https://github.com/defparam/smuggler

git clone https://github.com/swisskyrepo/SSRFmap
pip install -r SSRFmap/requirements.txt --break-system-packages

git clone https://github.com/vladko312/SSTImap
pip install -r SSTImap/requirements.txt --break-system-packages
```

> **Note on tplmap:** The project uses `SSTImap` under the hood for the `tplmap` tool key.
> The original epinna/tplmap is explicitly unmaintained and has Python-2-only parts.
> SSTImap is an actively maintained Python 3 rewrite built as a direct replacement.

### Verify

```bash
sqlmap --version
httpx-toolkit -version
crlfuzz -h
dalfox version
python3 ~/tools/XSStrike/xsstrike.py -h
python3 ~/tools/smuggler/smuggler.py -h
python3 ~/tools/SSRFmap/ssrfmap.py -h
python3 ~/tools/SSTImap/sstimap.py -h
```

---

## Known limitations

- **All real-mode tools are missing on macOS.** This is a Kali-first toolset. Mock mode works fully on any platform.
- **Real-mode HITL blocks on terminal input.** In a headless/CI environment, `TOOL_MOCK_MODE=true` auto-approves. Real mode requires a human at the terminal.
- **sqlmap timeout is 240 s** (it can be slow on hard targets). All other tools default to 60–120 s.
- **SSRFmap requires a request file, not a bare URL.** `tools.py` builds that file automatically from the target URL, but if the LLM doesn't pass the correct `param` name, SSRFmap will fuzz the wrong parameter.
- **The `tplmap` tool key runs SSTImap** (`~/tools/SSTImap/sstimap.py`), not the original tplmap, which is no longer maintained.

---

## Pipeline integration

When all five agents are running, chain them:

```python
import requests

target = "http://testphp.vulnweb.com/"

scout   = requests.post("http://localhost:8001/agents/agent-scout/tasks",
            json={"prompt": "Fingerprint the target.", "target": target, "context": {}}).json()
# ... mapper (8002), analyst (8003), prober (8004) ...
striker = requests.post("http://localhost:8005/agents/agent-striker/tasks",
            json={
                "prompt": "Validate injection points from Prober. Use HITL before each exploit.",
                "target": target,
                "context": prober["response"]
            }).json()
print(striker)
```

---

## File structure

```
agent-striker/
├── main.py              # FastAPI app — POST /tasks, GET /health, startup env check
├── agent.py             # LangGraph ReAct agent — AI logic, HITL gate, output saving
├── tools.py             # Tool registry with binary checks and ANSI stripping
├── httpx_parser.py      # Parser for httpx JSONL output
├── format_result.py     # CLI formatter — pipes response to markdown + JSON in results/
├── requirements.txt
├── env.example          # Copy to .env and fill in values
├── .env                 # Your local config (git-ignored)
├── outputs/             # Per-tool JSON files + final_response_*.json (auto-created)
└── README.md
```
