# agent-prober (Team 4)

F4 Active Scan (safe tier) specialist agent. Port 8004, agent_id `agent-prober`.

The agent accepts a natural-language prompt and a target URL, uses a local LLM
(Ollama) running a ReAct loop to decide which active scanning tools to run, runs
them, and returns structured findings. The keyword-rule planner (planner.py) is
kept as a fallback when Ollama is unreachable.

---

## Prerequisites

- Python 3.10+ (tested on 3.14 on macOS M3)
- Ollama installed and running locally (or a shared Ollama server URL from your mentor)
- The scanning binaries installed if you want real scans (nikto, testssl.sh, etc.)
  — mock mode works without any binaries at all

---

## Step 1 — Install Ollama and pull a model

On macOS:

```bash
brew install ollama
ollama serve          # starts the local server on port 11434, keep this running
ollama pull qwen2.5:7b   # ~4.7GB download, do this on wifi
```

On Linux/Kali:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve
ollama pull qwen2.5:7b
```

Verify Ollama is working:

```bash
curl http://localhost:11434/v1/models
# should return a JSON list containing qwen2.5:7b
```

If your mentor provides a shared Ollama server instead of running locally,
skip the `ollama serve` and `ollama pull` steps — just put the server URL
in your .env as OLLAMA_BASE_URL.

---

## Step 2 — Clone the repo and set up Python environment

```bash
cd /path/to/your/project
python3 -m venv .venv
source .venv/bin/activate   # on Windows: .venv\Scripts\activate
pip install fastapi uvicorn pydantic langgraph langchain-openai langchain-core openai python-dotenv
```

---

## Step 3 — Create your .env file

Copy the example and edit it:

```bash
cp .env.example .env
```

Contents of .env:

```
TOOL_MOCK_MODE=true
USE_REACT_AGENT=true
OLLAMA_BASE_URL=http://localhost:11434/v1
OLLAMA_MODEL=qwen2.5:7b
TOOL_TIMEOUT_SECONDS=300
PORT=8004
```

TOOL_MOCK_MODE=true means no real scanning binaries are needed — tools return
realistic canned output. Set to false only when you have the binaries installed
and an instructor-approved target to scan.

USE_REACT_AGENT=true means the LLM (Ollama) drives tool selection. Set to false
to fall back to the keyword-rule planner — useful if Ollama is unreachable.

---

## Step 4 — Start the service

You need two terminal windows open simultaneously.

Window 1 — Ollama server (keep running):

```bash
ollama serve
```

Window 2 — FastAPI service (keep running):

```bash
cd /path/to/project
source .venv/bin/activate
uvicorn main:app --port 8004 --reload
```

You should see:

```
INFO:     Uvicorn running on http://0.0.0.0:8004 (Press CTRL+C to quit)
```

---

## Step 5 — Verify the service is up

In a third terminal window:

```bash
curl http://localhost:8004/health
```

Expected response:

```json
{
  "agent_id": "agent-prober",
  "status": "ok",
  "mock_mode": true,
  "tool_allowlist": [
    "httpx",
    "nuclei_active",
    "testssl_deep",
    "ffuf",
    "wfuzz",
    "kxss",
    "corsy",
    "nikto",
    "wpscan_full",
    "droopescan"
  ]
}
```

If this works, the service is ready.

---

## Step 6 — Send a task

```bash
curl -X POST http://localhost:8004/agents/agent-prober/tasks \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Check TLS strength and look for CORS issues","target":"http://altoro.testfire.net/","context":{}}'
```

Expected response shape:

```json
{
  "agent_id": "agent-prober",
  "status": "completed",
  "response": {
    "summary": "...(LLM-written summary mentioning specific findings)...",
    "findings": [
      {
        "signal_candidates": ["weak_tls_version_or_ciphers"],
        "tools_used": ["run_httpx", "run_testssl_deep", "run_corsy"],
        "tool_errors": [],
        "details": [...]
      }
    ]
  },
  "error": null
}
```

The summary field is written by the LLM and will mention specific signals found
(e.g. "TLS 1.0 and TLS 1.1 are offered, which are outdated protocols"). It is
not a generic template — it reflects what the tools actually returned.

---

## Step 7 — Switch to real scans (optional)

Once you have the binaries installed and an instructor-approved target:

1. Change TOOL_MOCK_MODE=false in your .env
2. Restart uvicorn (Ctrl+C, then uvicorn main:app --port 8004 --reload)
3. Run httpx -version to confirm it is ProjectDiscovery's tool, not the Python
   pip package (same binary name, different program — see verification log below)
4. Run the curl again against your approved target

---

## Troubleshooting

"model 'llama3' not found"
Your .env has the wrong model name, or .env is not being loaded.
Check: python3 -c "from dotenv import load_dotenv; load_dotenv(); import os; print(repr(os.getenv('OLLAMA_MODEL')))"
Fix: make sure agent.py has "from dotenv import load_dotenv; load_dotenv()" at the top.

"Connection error" / status failed
Ollama is not running. Start it: ollama serve
Then check: curl http://localhost:11434/v1/models

Service starts but curl returns "Connection refused"
Uvicorn is not running. Start it in window 2.

"agent_id not found" / 404
The agent_id in your curl URL must be exactly "agent-prober".

Tools run but findings look wrong / mock-looking
TOOL_MOCK_MODE is still true, or the binary is not on PATH.
Check: which nikto, which testssl.sh, etc.

---

## How tool selection works

With USE_REACT_AGENT=true (default):
The LLM reads your prompt and each tool's output, then decides what to run
next. It always starts with httpx (live check), then reasons about what
the prompt is asking for and what previous tool output revealed. It stops
when it has enough to answer, not after a fixed number of tools.

With USE_REACT_AGENT=false (fallback):
planner.py uses keyword rules: "tls"/"ssl" -> testssl_deep, "cors" -> corsy,
"wordpress" -> wpscan_full, etc. Always runs httpx and nuclei_active by
default. Useful when Ollama is unreachable.

---

## Allowlist enforcement

tools.py::get_tool() raises PermissionError for any tool key not in
PROBER_ALLOWLIST. The FastAPI handler catches this and returns
status "failed" rather than crashing. Allowed tools:

httpx, nuclei_active, testssl_deep, ffuf, wfuzz, kxss,
corsy, nikto, wpscan_full, droopescan

---

## Real-tool verification log

Tested in a sandbox with restricted network egress. Real binary runs confirmed
against pypi.org as the test target (used only to capture output shapes).

Verified against real tool output, bugs found and fixed:

- nikto: does NOT support JSON output (only csv/htm/msf/nbe/xml/txt). XML mode
  tries to fetch a DTD over the network and fails in restricted environments.
  Fixed: wrapper parses the default "+ <finding>" stdout lines with -maxtime
  to bound scan length.

- corsy: -o flag writes to a real file path only, no stdout streaming mode.
  Fixed: wrapper writes to a temp file and reads it back.

- httpx: binary name collision — the Python httpx pip package installs a
  same-named CLI shim that exits 0 even when it cannot run. A naive return-code
  check would silently treat garbage as a successful scan. Fixed: wrapper
  validates stdout actually parses as real JSON-lines before trusting it.
  Before running for real, confirm: httpx -version mentions "projectdiscovery".

- testssl_deep: --jsonfile-pretty "-" is not a stdout convention, "-" is
  treated as a literal filename. Fixed: wrapper writes to a real temp file.
  Real schema confirmed: top-level scanResult list, per-target entry has
  nested protocol/vulnerability lists each containing {id, severity, finding}.

- droopescan: broken on Python 3.10+ (cement dependency imports removed imp
  module). Fixed with a minimal imp.py shim backed by importlib. Empty stdout
  on a non-CMS target is correct droopescan behavior, not a failure.

- wfuzz: same Python 3.10+ imp module breakage. Left unfixed — ffuf covers
  the same fuzzing capability.

- httpx data-loss bug: parse_output originally set live/status_code/title/tech
  keys only, but main.py's aggregation loop reads findings and signal_candidates.
  Since .get() defaults silently, this never crashed — it just silently dropped
  httpx data from every API response. Fixed by populating findings too.
  Regressed once on teammate merge, caught by end-to-end response assertion.

Not yet verified against real binaries (Go toolchain unavailable in sandbox):
nuclei_active, ffuf, kxss, wpscan_full. Parsers are schema-based estimates.
Verify by running real binary against an approved lab target and comparing
actual output to what parse_output() expects.

---

## Safety

- Only scan instructor-approved lab targets, or keep TOOL_MOCK_MODE=true.
- Never point this at production systems without written approval.
- Real subprocess execution requires TOOL_MOCK_MODE=false AND the binary on PATH.
- Do not commit .env to git. Use .env.example instead.


Let me build this from the absolute ground up so every piece makes sense before the next one is introduced.

---

##The problem being solved##

When a company wants to know if their website is secure, they hire security testers to find vulnerabilities before attackers do. A vulnerability is a weakness in a system that an attacker can exploit to do something they should not be able to do — read data they should not see, run commands on the server, impersonate other users, and so on.

A tester doing this manually runs tools one at a time. They run a tool, read its output, think about what it means, decide what to run next based on what they found, run another tool, repeat. This process is slow, requires deep expertise, and the quality of the assessment depends entirely on how experienced the tester is.

Your project is building a system called Obsidia that automates this reasoning loop. Instead of a human tester doing the think-decide-act cycle manually, software does it. Your specific piece is called agent-prober. It is responsible for one phase of the assessment — the active scanning phase, where you actually send probes to the target and look for real vulnerabilities.

---

##The four phases of a web security assessment — why they exist in this order##

Before you can test for vulnerabilities, you need to know what you are testing. The assessment is split into four families, run in sequence:

F1 — Fingerprinting. Find out what the target actually is. What web server is it running. What programming language. What framework. What version. Is there a firewall in front of it. This phase answers "what are we looking at" before doing anything else. Running attack tools against something you have not fingerprinted first is like trying to pick a lock without knowing what kind of lock it is.

F2 — Surface Enumeration. Map everything that exists on the target. What URLs and routes are there. What JavaScript files. What API endpoints. What ports are open. This phase answers "what is the attack surface" — you cannot test endpoints you do not know exist.

F3 — Passive Scan. Analyse what was collected in F2 without sending aggressive probes. Look for secrets accidentally left in JavaScript files. Look for known-vulnerable library versions. Look for configuration hints that suggest problems. This phase finds the low-hanging fruit without touching the target aggressively.

F4 — Active Scan. Now that you know what exists, actually probe it for vulnerabilities. Send payloads. Test cipher suites. Fuzz for hidden paths. Check for misconfigurations. This is what agent-prober does.

The order matters. You do not run F4 tools against endpoints you have not mapped in F2. You do not map the surface in F2 before confirming the target is live in F1. Each phase feeds the next.

---

##What a web API is and why your agent is one##

An API is an Application Programming Interface. It is a way for two programs to communicate with each other over a network. The communication follows the HTTP protocol — HyperText Transfer Protocol, the same protocol your browser uses to load websites.

In HTTP, a client sends a request to a server. The request has a method (GET means "give me this resource", POST means "here is some data, do something with it"), a path (which resource you are talking to), and optionally a body (the data you are sending).

The server sends back a response with a status code (200 means success, 404 means not found, 500 means the server crashed) and optionally a body (the data coming back).

Your agent-prober is an HTTP server. It listens on port 8004 on your machine. When another program or a human sends it an HTTP POST request with a prompt and a target URL, it does security scanning work and sends back an HTTP response with structured findings. The data format for both the request and response is JSON — JavaScript Object Notation, a text format for representing structured data as nested key-value pairs.

---

##What FastAPI is##

Writing raw HTTP server code from scratch — managing TCP sockets, parsing HTTP text, routing requests to the right functions — is tedious and error-prone. FastAPI is a Python library that handles all of this for you.

You write Python functions and decorate them with annotations. FastAPI registers those functions as handlers for specific URL paths and HTTP methods. When a request arrives, FastAPI parses it, validates the data against schemas you define, calls your function with clean structured data, and serialises your return value back to JSON.

Uvicorn is the program that actually opens the network socket and listens for connections. FastAPI defines the routing and business logic. Uvicorn is the engine that runs it. When you run:

```
uvicorn main:app --port 8004 --reload
```

You are telling uvicorn: load the app object from main.py, listen on port 8004, and restart automatically when any Python file changes.

Pydantic is what validates incoming data. You define a class describing the expected shape of a request:

```python
class TaskRequest(BaseModel):
    prompt: str
    target: str
    context: dict
```

FastAPI uses this to check every incoming request. If the JSON body is missing the prompt field or has the wrong type, FastAPI rejects it with a clear error before your code even runs. This means your function is always called with guaranteed-valid data.

---

##What the tools are and what each one does##

Your agent has ten tools in its allowlist. Each one is a command-line security program that already exists, written by other people. Your code does not reimplement any of them. It wraps each one — knows how to start it, capture its output, and parse the results into a standard format.

httpx (ProjectDiscovery's recon tool, not the Python library of the same name — important distinction, they share a name but are completely different programs) — sends an HTTP request to the target and reports back whether it is alive, what status code it returned, what the page title is, and what technologies it detected. Always runs first to confirm the target is reachable before wasting time with other tools.

nuclei_active — runs a large library of templates against the target. Each template is a small test for one specific issue — "does this server have a Content Security Policy header", "is there a .git directory exposed", "does this URL respond to a known CVE payload". Runs thousands of these tests efficiently.

testssl_deep — analyses the TLS configuration of the target. TLS is the encryption protocol that makes HTTPS work. Old versions of TLS (1.0, 1.1) have known weaknesses. Weak cipher suites can be exploited. testssl checks all of this and reports what the server supports.

ffuf — directory and path fuzzer. It takes a wordlist (a large file of common path names like "admin", "backup", "config", "login") and tries each one as a URL path on the target. Anything that returns a non-404 response is reported as a finding. This finds hidden admin panels, accidentally exposed backup files, debug endpoints, and configuration files.

kxss — reflected XSS tester. XSS is Cross-Site Scripting — a vulnerability where an attacker injects JavaScript into a web page that then runs in other users' browsers. kxss takes a URL with parameters and tests whether special characters like angle brackets and quotes are reflected back in the response unfiltered, which is the condition that allows XSS.

corsy — CORS misconfiguration scanner. CORS is Cross-Origin Resource Sharing — a browser security mechanism that controls which websites can make requests to your API from their JavaScript. A misconfigured CORS policy can allow a malicious website to make authenticated requests to your API and read the responses on behalf of a logged-in user.

nikto — general web server scanner. Sends a large number of probes looking for known misconfigurations, dangerous default files, outdated software banners, and missing security headers. Broad coverage but not deep on any single issue.

wpscan_full — WordPress-specific scanner. WordPress is the most widely used content management system on the internet. It has a large ecosystem of plugins and themes, many of which have known vulnerabilities. wpscan enumerates the WordPress version, all installed plugins and their versions, all themes, and matches them against a vulnerability database.

droopescan — similar to wpscan but for Drupal, SilverStripe, Joomla, and Moodle — other content management systems with their own vulnerability ecosystems.

wfuzz — another fuzzer, similar purpose to ffuf. Currently broken on Python 3.10+ due to an unmaintained dependency, so ffuf covers its role.

---

##What tools.py does##

tools.py is the file containing all ten tool wrappers. Each wrapper is a Python class that knows three things about its tool:

How to build the exact command-line invocation. For example, nikto's wrapper knows to run:
```
nikto -h <target> -maxtime 100s -nointeractive
```

How to parse the raw output. This was the hardest part. Each tool outputs data in a completely different format — nikto prints plain text with + signs at the start of finding lines, testssl.sh writes JSON to a file (not stdout), corsy also writes to a file rather than printing to stdout, nuclei outputs JSON-lines (one JSON object per line). Each wrapper has a parse_output() function that reads whatever format its tool produces and converts it into a standard dictionary.

What to return when the tool is not available. Every wrapper has a mock_output() function that returns a realistic pre-written result. When TOOL_MOCK_MODE=true in your .env file, every tool call returns this mock data instead of running the real binary. This means the entire agent works for development and demo purposes without needing every security tool installed.

The standard output shape every wrapper must return is:

```python
{
    "tool_name": "nikto",
    "family_id": "F4",
    "target": "http://...",
    "signal_candidates": ["missing_security_headers"],
    "findings": [...],
    "errors": []
}
```

signal_candidates is a list of short labels from a controlled vocabulary defined in the doctrine workbook — things like missing_security_headers, weak_tls_version_or_ciphers, exposed_git, vulnerable_plugin_detected. These are the same signal keys you wrote glossary entries for during Day 11. They are how the system communicates what category of issue was found, in a machine-readable way.

This uniform shape is what makes it possible to combine results from ten completely different tools — each with different output formats, different ways of running, different kinds of findings — into one coherent response. The aggregation code in main.py does not need to know anything specific about any individual tool. It just reads findings and signal_candidates from whatever came back.

---

## What a language model is ##

A language model is a mathematical function. It takes a sequence of tokens as input — tokens are chunks of text, roughly corresponding to words and punctuation but not exactly — and outputs a probability distribution over what token should come next.

If the input tokens are "The sky is", the model might output a distribution where "blue" has high probability, "clear" has moderate probability, "dark" has lower probability, and so on for every token in its vocabulary (typically 50,000 to 100,000 tokens).

You generate text by repeating this process: sample a token from the distribution, append it to the sequence, feed the whole thing back in, get the next distribution, sample again. This is called autoregressive generation.

The parameters of the model — the numbers that determine the probability distributions — are learned during training. Training works by showing the model enormous amounts of text (web pages, books, code, documentation, conversations — essentially the text content of the internet) and repeatedly adjusting the parameters to make the model better at predicting what comes next. A model with 7 billion parameters (7B) has 7 billion numbers that get tuned during this process.

The reason this produces intelligent-seeming behaviour is that predicting what comes next in human-written text requires implicitly learning an enormous amount about language, facts, reasoning, and human thought. The model did not learn "TLS 1.0 is a weak protocol" as an explicit rule. It learned to predict text, and because security documentation consistently follows "TLS 1.0" with statements about it being deprecated and insecure, the model has encoded that association in its parameters.

temperature=0 in your code means no randomness in token sampling — always pick the highest probability token. You want this for an agent because you want reliable, deterministic decisions, not creative variation.

---

## What Ollama is ##

Running inference on a 7 billion parameter model requires loading approximately 4-5 gigabytes of numbers into memory and doing billions of floating point multiplications for each token generated. This used to require expensive server hardware.

Ollama is a program that manages local LLM inference on consumer hardware. It handles loading the model file into memory, running inference efficiently using your hardware's capabilities, and exposing the results via an HTTP API.

On your M3 MacBook Air, Ollama uses Apple's Metal framework to run inference on the GPU. Apple Silicon chips have unified memory — the CPU and GPU share one physical pool of RAM rather than having separate CPU RAM and GPU VRAM. This means a 7B model that would normally require a dedicated GPU with its own VRAM can run efficiently on your laptop's shared memory pool.

The OpenAI-compatible API means Ollama exposes an HTTP endpoint that speaks exactly the same protocol format as OpenAI's cloud API. The same request that would go to OpenAI's servers at api.openai.com works identically when sent to localhost:11434 — only the URL and model name change. This is why the Python openai library works with Ollama without any modification.

qwen2.5:7b is the specific model you are running. Qwen 2.5 is a model family developed by Alibaba's research team. The 7B variant has 7 billion parameters. It is particularly strong at instruction-following and structured tool-calling, which is why it was chosen — your agent needs the model to reliably pick the right tool and format its response correctly, not to be creative.

---

##What ReAct is##

ReAct stands for Reason and Act. It is a pattern for using a language model to drive a decision loop rather than just generating a single response to a single question.

The core idea is that instead of asking the model to answer everything at once from the prompt alone, you give it tools it can call, and you run a loop where the model alternates between reasoning about what it knows and acting by calling a tool. After each tool call, the result is fed back to the model, which reasons again and decides what to do next. This continues until the model decides it has enough information to write a final answer.

One complete iteration of the loop looks like this. The model generates the Thought and Action. Your code executes the Action and feeds back the Observation:

```
Thought: The prompt asks me to check if the site is live first.
         I should run httpx before anything else.
Action: run_httpx("http://altoro.testfire.net")
Observation: {"live": true, "status_code": 200, "tech": ["nginx"]}

Thought: Target is live. Now I should check TLS as the prompt asked.
Action: run_testssl_deep("http://altoro.testfire.net")
Observation: {"findings": [{"id": "TLS1", "finding": "TLS 1.0 offered"}]}

Thought: TLS 1.0 is weak. Prompt also asked about CORS. Let me check that.
Action: run_corsy("http://altoro.testfire.net")
Observation: {"findings": [], "signal_candidates": []}

Thought: No CORS issues. Prompt asked about directory fuzzing.
Action: run_ffuf("http://altoro.testfire.net")
Observation: {"findings": [{"input": "backup.zip", "status": 200}]}

Thought: Found a backup file. Prompt asked about WordPress plugins.
Action: run_wpscan_full("http://altoro.testfire.net")
Observation: {"findings": [{"type": "core_version", "number": "5.8", ...}]}

Thought: WordPress 5.8 has known vulnerabilities. Prompt asked for
         general active scan too.
Action: run_nuclei_active("http://altoro.testfire.net")
Observation: {"findings": [{"template_id": "missing-csp-header", ...}]}

Thought: I have covered everything the prompt asked for. Writing final answer.
Final Answer: The target is live. TLS 1.0 and 1.1 are offered...
```

The critical property is that each Action is chosen after reading the previous Observation. The model never had a plan for all six tools simultaneously. It decided one tool at a time based on everything it had learned up to that point.

The proof in your response was that kxss, nikto, and droopescan were never called even though they are in the allowlist and the prompt said "run a general active scan for any other misconfigurations." The model read nuclei_active's output, concluded that the prompt had been fully addressed, and stopped. That conclusion was only possible by reading tool outputs dynamically and reasoning about whether the task was complete — a keyword planner has no mechanism to do this.

---

##What LangChain is##

LangChain is a Python library providing abstractions for working with language models. Two things from it appear in your code.

The @tool decorator. This turns a regular Python function into a structured tool object that LangGraph can work with. The function name becomes the tool name. The docstring becomes the tool description — this is literally what the LLM reads to understand what the tool does. The function parameters define what arguments the LLM must provide when calling it. When you write:

```python
@tool
def run_testssl_deep(target: str) -> str:
    """Run a deep TLS/SSL analysis on the target. Checks for weak protocol
    versions (TLS 1.0, TLS 1.1, SSLv3). Use when the prompt mentions TLS,
    SSL, ciphers, certificates, or HTTPS security."""
    return _run("testssl_deep", target)
```

The LLM sees "run_testssl_deep: Run a deep TLS/SSL analysis on the target..." and uses that description to decide whether this is the right tool for what the current situation requires.

ChatOpenAI. This is LangChain's class for talking to any OpenAI-format API, including Ollama. It handles formatting messages correctly, sending HTTP requests, and parsing responses.

---

##What LangGraph is##

The ReAct loop is a loop with a conditional exit condition. You could write it manually in Python. But the loop gets complicated fast — what if you want some nodes to run in parallel, what if you want to add a human review step between certain tool calls, what if the model crashes halfway through and you want to resume, what if you want different stopping conditions in different situations.

LangGraph is a library that models the ReAct loop as a state machine graph. A graph has nodes and edges. Each node is a Python function that does some work and returns updated state. An edge connects one node to the next. A conditional edge goes to different nodes depending on some condition.

State is a dictionary that gets passed between nodes and accumulates everything as the loop runs — the original prompt, all messages so far (user messages, LLM responses, tool calls, tool results), anything else you want to track.

Your agent's graph has roughly this structure:

```
[start]
    ↓
[call_llm] ←─────────────────┐
    ↓                         │
[check_response]              │
    ↓ if tool call            │
[execute_tool] ───────────────┘
    ↓ if final answer
[end]
```

The check_response node is the conditional edge. It looks at what the LLM returned. If the LLM produced a tool call, route to execute_tool and then back to call_llm. If the LLM produced plain text with no tool call, route to end and return the answer.

create_react_agent() is a prebuilt LangGraph function that builds exactly this graph. You give it the LLM and tools:

```python
agent_graph = create_react_agent(llm, AGENT_TOOLS, prompt=SYSTEM_PROMPT)
result = agent_graph.invoke(
    {"messages": [("user", full_prompt)]},
    config={"recursion_limit": 20}
)
```

invoke() runs the full graph — every Thought → Action → Observation cycle — until the LLM produces a final answer. recursion_limit=20 is a safety cap so the loop cannot run forever.

---

##How the message history accumulates##

Every message in the conversation is stored in result["messages"] in order. After a complete run it looks like this:

HumanMessage — your original prompt
AIMessage with tool_calls — LLM's first response, specifying which tool to call
ToolMessage — the output of that tool call
AIMessage with tool_calls — LLM's second response, specifying the next tool
ToolMessage — that tool's output
(repeating for each tool called)
AIMessage with text content — LLM's final answer, no tool call this time

The final AIMessage's content is the summary in your API response. The ToolMessages are what agent.py loops through to collect findings and signal_candidates for the structured findings block.

---

##How everything connects — the complete data flow##

You send a POST request to localhost:8004/agents/agent-prober/tasks with a JSON body containing your prompt, target, and context.

Uvicorn receives the TCP connection on port 8004 and hands it to FastAPI.

FastAPI parses the HTTP request and validates the JSON body against TaskRequest using Pydantic. If anything is missing or wrong type, it rejects immediately with a 422 error.

main.py checks agent_id == "agent-prober". If not, returns 404. Then checks USE_REACT_AGENT=true and calls run_react_agent() from agent.py.

agent.py builds the full prompt string combining your instruction, target URL, and any upstream context. Calls create_react_agent(llm, AGENT_TOOLS) to build the LangGraph graph. Calls invoke() to run it.

LangGraph starts the graph. First node sends the full prompt to qwen2.5:7b via HTTP POST to localhost:11434/v1/chat/completions — Ollama's OpenAI-compatible endpoint.

qwen2.5:7b generates an AIMessage containing a structured tool call specifying which function to invoke and with what arguments. It chose this tool by reading the tool docstrings and matching them against the prompt semantically.

LangGraph's conditional edge sees this is a tool call, routes to the tool execution node, which calls your @tool function in agent.py.

Your @tool function calls _run(tool_key, target), which calls get_tool(tool_key).run(target) from tools.py.

If TOOL_MOCK_MODE=true, the wrapper's mock_output() returns pre-written data. If false, the wrapper runs the real binary as a subprocess using Python's subprocess.run(), captures its output, and parse_output() converts it to the standard dict.

The result is serialised to a compact JSON string and added to the message history as a ToolMessage. LangGraph routes back to the call_llm node.

qwen2.5:7b reads the entire message history — original prompt plus all tool outputs so far — and generates its next response. Another tool call, or a final answer.

This cycle repeats until qwen generates a final text answer. LangGraph exits the graph.

agent.py loops through result["messages"], collects all ToolMessage contents into findings and signal_candidates, takes the last AIMessage as the summary, returns the standard response dict.

main.py wraps this in a TaskResponse and returns it.

FastAPI serialises to JSON, uvicorn sends the HTTP response, your terminal prints the result.

---

##How this connects to your earlier internship work##

Day 11 signal glossary — you defined what signals like missing_security_headers, weak_tls_version_or_ciphers, and exposed_git mean, how to distinguish them from noise, and which tool family detects them. The signal_candidates lists your tool wrappers emit use exactly this vocabulary. The LLM reads those signal names in the Observation step and uses them to reason about what to do next.

Day 12 doctrine classification — you classified workbook cells into Category A (compilable logic like route_growth_rate < 0.05), Category B (human prose), and Category C (controlled vocabulary like signal keys and tool names). The signal_candidates vocabulary is Category C. The LLM's reasoning about what to do next is Category B. The condition compiler evaluating whether to advance to the next family is Category A. Your agent implements the Category B reasoning layer.

Day 13 parsers — you built wpscan_parser.py, nirjas_parser.py, jshole_parser.py following a strict 7-key output contract. Your tools.py wrappers follow the same philosophy — every tool returns the same shape regardless of what it is. This uniform contract is what makes the aggregation layer in main.py simple and tool-agnostic.

Day 18 condition compiler — you built the system that evaluates Category A conditions against MissionState at runtime. That is the automated routing layer that decides when to move between families based on metrics like js_bundle_count >= 20. Your agent-prober is what gets executed when F4 conditions are met.

Day 19 LLM call sites — you defined the five places Obsidia calls an LLM: Mission Planner, Guided Reasoning, Exploratory Reasoning, Snapshot Critic, Semantic Compressor. Your agent-prober implements a version of Guided Reasoning — using an LLM to decide which tools to run next based on what previous tools found, which is exactly what the Guided Reasoning call site was designed for.

---

##The one-sentence version for the demo##

agent-prober is a FastAPI web service that receives a natural-language security task, uses qwen2.5:7b running locally via Ollama in a LangGraph ReAct loop to dynamically decide which active scanning tools to run against the target one at a time based on what each previous tool found, executes those tools and parses their output into a standard format, and returns a structured JSON response containing both a human-readable LLM-written summary and machine-readable findings with signal keys — replacing what would otherwise be a human security tester manually running CLI tools and reasoning about their output.