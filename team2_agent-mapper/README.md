# Agent Mapper — Team 2
**Entersoft ReconAgent Program | PS-1 Internship 2026**
Students: Ishaan Agarwal, Nitya Sri Ravuri
Agent ID: `agent-mapper` | Port: `8002`

---

## What This Agent Does

Agent Mapper performs **F2 Surface Enumeration** — given a target URL, it maps
the full attack surface: open ports, reachable endpoints, JavaScript files,
API paths, hidden directories, and source map files.

It accepts a natural-language prompt, selects the right tools based on what
the prompt asks for, runs them against the target, and returns structured JSON findings.

---

## Project Structure

```
agent-mapper/
├── main.py          # FastAPI service — endpoints and agent logic
├── tools.py         # Wrapper classes for all 10 tools + TOOL_REGISTRY
├── .env             # Your local environment variables (not committed)
├── .env.example     # Template for .env
└── README.md        # This file
```

---

## Setup

### 1. Clone or copy the project folder onto your Kali machine

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install fastapi uvicorn python-dotenv
```

### 4. Set up environment variables

```bash
cp .env.example .env
```

Open `.env` and set:

```
TOOL_MOCK_MODE=true    # use fake outputs (no real scans)
TOOL_MOCK_MODE=false   # use real installed tools
```

### 5. (Optional) Install scan tools on Kali

Only needed when `TOOL_MOCK_MODE=false`:

```bash
# Go-based tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest

# Python-based tools
pip install dirsearch
pip install nirjas

# jsluice
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

# nmap (usually pre-installed on Kali)
sudo apt install nmap
```

---

## Running the Agent

```bash
# Make sure your venv is active
source venv/bin/activate

# Load env vars and start the server
export $(cat .env | xargs)
uvicorn main:app --reload --port 8002
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8002 (Press CTRL+C to quit)
```

---

## Testing the Endpoints

### Health check

```bash
curl http://localhost:8002/health
```

Expected response:
```json
{
  "agent_id": "agent-mapper",
  "status": "ok",
  "port": 8002,
  "allowed_tools": ["dirsearch", "gau", "httpx", "jsluice", "katana",
                    "naabu", "nirjas", "nmap_service", "source_maps_downloader",
                    "waybackurls"]
}
```

---

### Sample prompt from the assignment doc

```bash
curl -X POST "http://localhost:8002/agents/agent-mapper/tasks" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Map all routes, JS files, API paths, and open ports for https://target.example.com.",
    "target": "https://target.example.com",
    "context": {}
  }'
```

Expected response shape:
```json
{
  "agent_id": "agent-mapper",
  "status": "completed",
  "response": {
    "summary": "Ran 10 tools against https://target.example.com. 10 succeeded, 0 failed.",
    "tools_run": ["httpx", "naabu", "katana", "gau", "waybackurls",
                  "dirsearch", "jsluice", "nirjas", "source_maps_downloader", "nmap_service"],
    "findings": [
      {
        "tool": "httpx",
        "status": "success",
        "result": { "live": true, "status_code": 200, "server": "nginx/1.18.0" }
      }
    ]
  }
}
```

---

### Pipeline mode (Week 3 — with Scout context)

Pass Scout's findings as `context`:

```bash
curl -X POST "http://localhost:8002/agents/agent-mapper/tasks" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Map all routes and open ports.",
    "target": "https://target.example.com",
    "context": {
      "live": true,
      "server": "nginx",
      "technologies": ["PHP", "nginx"]
    }
  }'
```

When `context.live` is `true`, the agent skips the `httpx` verification step
since Scout already confirmed it.

---

## Tool Allowlist

The following tools are the only ones this agent is permitted to call.
Any tool name outside this list is silently dropped before execution.

| Tool | Purpose |
|---|---|
| `httpx` | Confirm target is live, grab HTTP metadata |
| `naabu` | Fast port scanning |
| `katana` | Web crawler — discovers URLs and endpoints |
| `gau` | Historical URLs from multiple archive sources |
| `waybackurls` | URLs from Wayback Machine specifically |
| `dirsearch` | Directory and path brute-forcing |
| `jsluice` | Extract endpoints and secrets from JS files |
| `nirjas` | Extract comments from source files |
| `source_maps_downloader` | Detect exposed .map files |
| `nmap_service` | Service and version detection on open ports |

---

## Environment Variables

| Variable | Values | Description |
|---|---|---|
| `TOOL_MOCK_MODE` | `true` / `false` | Use fake tool outputs instead of real scans |

---

## Error Handling

- If a tool crashes or times out, the agent records it as `status: error` and continues with remaining tools — it does not crash the whole request.
- If the entire agent errors, the endpoint returns `status: failed` with an error message rather than an HTTP 500.
- Timeout per request: 5 minutes (enforced by the assignment spec).
