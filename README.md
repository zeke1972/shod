# Ollama & OpenAI REST API Probe CLI

A fast and lightweight Python CLI tool to probe Ollama instances on `{ip}:{port}` (defaulting to 11434, `OLLAMA_PORT`, or custom target ports) running [Ollama](https://ollama.com). It queries Ollama's native model listing endpoint (`/api/tags`), tests the OpenAI-compatible REST API endpoint (`/v1/models`), detects unauthorized instances (HTTP 401 / 403), benchmarks chat completion reply speed (`/v1/chat/completions`), and provides a full interactive chat REPL with dynamic model selection.

---

## Features

- **Direct Command-Line Target Input**: Pass one or more IPs or hostnames directly on the CLI.
- **Native Ollama Inspection (`/api/tags`)**: Lists models with their ID, size (in GB/MB), parameter size, quantization format, and modified date.
- **OpenAI REST API Test (`/v1/models`)**: Validates the OpenAI-compatible REST endpoint response schema, HTTP status, and model IDs.
- **Unauthorized & Authentication Detection**:
  - Automatically identifies whether an instance is **Open / Unauthenticated** (HTTP 200 / 404) vs **Unauthorized / Auth Required** (HTTP 401 Unauthorized / HTTP 403 Forbidden).
  - Checks authorization status for **both discovery and chat inference APIs**:
    - Discovery: `/api/tags` and `/v1/models`
    - Chat: Native `/api/chat` and OpenAI `/v1/chat/completions`
  - Uses fast non-intrusive probe requests that detect authorization within milliseconds without triggering multi-minute cold weight loads.
  - Extracts server authentication failure messages.
  - Interactive credential prompt when launching chat against an authenticated target.
  - Supports `--api-key <key>` or `OPENAI_API_KEY` / `OLLAMA_API_KEY` environment variables.
- **REST API Chat Speed Evaluation (`/v1/chat/completions`)**:
  - Measures total latency and Time To First Token (TTFT).
  - Calculates tokens per second (`tok/s`) generation throughput.
  - Displays token count and reply preview.
- **Interactive Chat with Model Selection**:
  - Interactive numbered model selection menu on connect.
  - Real-time token-by-token streaming reply.
  - Live speed statistics footer after each turn (`⏱ 1.4s | 28 tokens | 20.0 tok/s | TTFT: 150ms`).
  - In-chat slash commands: `/model` (switch models on the fly), `/clear`, `/history`, `/system`, `/info`, `/exit`.
- **IP Range & Subnet Scanning (`--range`, `-r`)**:
  - Scan IP ranges via CIDR notation (`192.168.1.0/24`, `10.0.0.0/16`, `127.0.0.1/30`), hyphen range (`192.168.1.1-192.168.1.50`, `192.168.1.1-50`), or wildcard (`192.168.1.*`).
  - Scans Ollama port 11434 (or custom `-p`) and tests the OpenAI REST API (`/v1/models`).
  - Supports `--threads` / `-T` for concurrent multi-threaded range scanning.
  - Seamlessly integrates with `-v` (sliding ETA), `-db` (DuckDB persistence/caching), `-o` (OpenAI only), `--force`, `--quiet`, and `--json`.
- **Batch & Pipeline Friendly**:
  - Read targets from files or `stdin` (ideal for Shodan or masscan sweeps).
  - Compact summary table mode (`--quiet`) with dedicated `TAGS`, `OPENAI`, and `CHAT` status columns (`OPEN`, `AUTH`, `401 AUTH`, `403 FORBID`).
  - Full machine-readable JSON output (`--json`).
- **DuckDB Database Persistence & Caching (`-db`)**:
  - Automatically queries DuckDB before probing any target host to prevent duplicate scanning.
  - Rehydrates cached scan reports and model tables instantly.
  - `--force` flag forces re-checking of single IP or entire files of IPs, updating database records.
  - Built-in `--db-summary` metrics and `--db-query` SQL execution.
- **Web Dashboard on Port 2000 (`web_dashboard.py` / `--dashboard`)**:
  - Zero-dependency web UI running on `http://localhost:2000`.
  - Real-time search and multi-dimensional filtering across target scan records and discovered models.
  - Interactive Models Registry with host popularity and open host metrics.
  - In-browser DuckDB SQL Studio with presets and CSV/JSON export.
  - On-demand Live Target Prober with instant DuckDB persistence.
  - Export filtered lists as plain `IP:PORT` text, CSV, or JSON.
- **Rich & Plain Output**: Automatically formats tables and status panels using `rich` if present, with clean ASCII fallback.

---

## Requirements

- Python 3.8+
- Recommended packages:
  ```bash
  pip install requests rich duckdb
  ```
  *(Note: The CLI includes fallbacks for standard library `urllib` and plain text if third-party packages are not installed).*

---

## Quick Start

### 1. Check If Ollama Chat is Authorized / Open
Verify whether Ollama chat endpoints (`/api/chat` and `/v1/chat/completions`) are open to the network or require authentication:
```bash
# Standard probe (automatically checks tags, openai, and chat authorization):
python3 ollama_cli.py 127.0.0.1

# Explicit chat check / auth check:
python3 ollama_cli.py 127.0.0.1 --check-chat
# Or using the positional shortcut:
python3 ollama_cli.py auth 127.0.0.1
```

#### Output Example (Open Host):
```text
╭────────── Ollama Host Report: http://127.0.0.1:11434 (v0.17.7) ──────────╮
│ ✔ Native Ollama API (/api/tags): 200 OK (1 models, 9.5ms)                │
│ ✔ OpenAI REST API (/v1/models): 200 OK Compatible (1 models, 5.0ms)      │
│ ✔ Native Chat API (/api/chat): OPEN (no auth required, 5.9ms)            │
│ ✔ OpenAI Chat API (/v1/chat/completions): OPEN (no auth required, 5.1ms) │
│ ✔ Parity Check: Native models and OpenAI models match exactly.           │
╰──────────────────────────────────────────────────────────────────────────╯
```

#### Output Example (Protected / Unauthorized Host):
```text
╭────────────── Ollama Host Report: http://10.0.0.2:11434 ────────────────╮
│ 🔒 Native Ollama API (/api/tags): UNAUTHORIZED (HTTP 401)                │
│ 🔒 OpenAI REST API (/v1/models): UNAUTHORIZED (HTTP 401)                 │
│ 🔒 Native Chat API (/api/chat): UNAUTHORIZED (HTTP 401)                  │
│ 🔒 OpenAI Chat API (/v1/chat/completions): UNAUTHORIZED (HTTP 401)       │
│ 🔑 Authentication Required: Target requires authorization (--api-key)    │
╰──────────────────────────────────────────────────────────────────────────╯
```

---

### 2. Run Models Directly (`ollama run` syntax)
Run any model directly with single-turn prompt execution, piped input, or interactive session, just like the official `ollama run` command:

```bash
# Run model in interactive chat session (defaults to 127.0.0.1:11434):
python3 ollama_cli.py run smollm2:135m

# Execute a single prompt directly and stream reply:
python3 ollama_cli.py run smollm2:135m "Why is the sky blue?"

# Run model on a remote target host:
python3 ollama_cli.py run 138.201.222.238 smollm2:135m "What is 2+2?"
# Or specifying host first:
python3 ollama_cli.py 138.201.222.238 run smollm2:135m

# Pipe prompts via standard input (UNIX pipeline friendly):
echo "Translate to French: Good morning" | python3 ollama_cli.py run smollm2:135m
cat code.py | python3 ollama_cli.py run smollm2:135m > review.txt

# Run with a system prompt:
python3 ollama_cli.py run smollm2:135m "Hello" --system "You are a concise AI assistant."

# Pull a model directly from the Ollama registry:
python3 ollama_cli.py pull llama3
```
*Note: If a model is not found on the Ollama instance, `run` will automatically attempt to pull it from the registry with real-time download progress.*

---

### 3. Interactive Chat with Model Selection
Connect to any target host to interactively choose a model and start chatting:
```bash
python3 ollama_cli.py chat 127.0.0.1
# Or using the flag:
python3 ollama_cli.py 192.168.1.50 --chat
```

#### In-Chat Slash Commands
| Command | Description |
| :--- | :--- |
| `/model` | Interactively switch to another model without exiting |
| `/model <name>`, `/run <name>` | Switch directly to specified model (supports `<Tab>` completion) |
| `/file <path> [prompt]` | Load local file into chat context with optional prompt instructions (supports `<Tab>` path completion) |
| `/paste` or `/multiline` | Enter dedicated multi-line paste mode (finish with `/send` or `/end`, abort with `/cancel`) |
| `/clear` | Clear conversation history context |
| `/history` | Show message count and preview conversation turns |
| `/system <prompt>` | Set or update the system prompt |
| `/info` | Display host, model, and context statistics |
| `/help` | Show command list and input tips |
| `/exit` or `/quit` | Exit chat session (or press `Ctrl+D` / double `Ctrl+C`) |

#### Ergonomic Input Entry Features
- **Multi-Line Line Continuation (`\`)**: End any line with a trailing backslash `\` to continue writing on the next line (`...  `).
- **Triple-Quote Block Input (`"""` or `'''`)**: Start a prompt with `"""` or `'''` to enter multi-line blocks of code, configuration, or free-form text. The input terminates automatically when the matching triple quote is closed.
- **Dedicated `/paste` Mode**: Type `/paste` or `/multiline` to paste large blocks of arbitrary code or text without accidental command triggering. Finish by entering `/send` on a new line or pressing `Ctrl+D`.
- **Context-Aware Tab Completion**:
  - Type `/` and press `<Tab>` to autocomplete slash commands.
  - Type `/model ` and press `<Tab>` to autocomplete model names from the target host.
  - Type `/file ` and press `<Tab>` to autocomplete local file paths and directories.
- **Persistent Command History**: Automatically saves and loads history across sessions in `~/.ollama_cli_history`. Use Up/Down arrows to navigate previous entries, or `Ctrl+R` for interactive reverse search.
- **Accidental Exit Protection**: Pressing `Ctrl+C` cancels the current input line without terminating the chat session. Press `Ctrl+C` twice within 2 seconds, press `Ctrl+D`, or type `/exit` to cleanly exit.
- **ANSI Cursor Alignment Fix**: Readline prompts use `\001` and `\002` escape delimiters to ensure backspace and line navigation never visually misalign or corrupt prompt text.

---

### 3. Authenticating with Protected Targets
When probing hosts behind proxies (e.g. Kong, LiteLLM, Traefik, Caddy, Cloudflare) requiring an API key:

```bash
# Authenticate using an API key / Bearer token:
python3 ollama_cli.py 192.168.1.100 --api-key "sk-mysecretkey"

# Or using environment variables:
export OPENAI_API_KEY="sk-mysecretkey"
# or:
export OLLAMA_API_KEY="sk-mysecretkey"
python3 ollama_cli.py 192.168.1.100
```

#### Quiet Mode Multi-Target Sweeps
```bash
python3 ollama_cli.py -f shodan_ips.txt --quiet
```
```text
TARGET                       TAGS       OPENAI     CHAT       MODELS   SPEED        LATENCY
-------------------------------------------------------------------------------------------
http://10.0.0.1:11434        OK         OK         OPEN       2        14.2 t/s     4.2ms
http://10.0.0.2:11434        401 AUTH   401 AUTH   401 AUTH   0        —            12.8ms
http://10.0.0.3:11434        ERR        ERR        ERR        0        —            N/A
```

---

### 4. REST API Reply Speed Benchmark
Evaluate the response speed and tokens/second throughput of `/v1/chat/completions`:
```bash
python3 ollama_cli.py 127.0.0.1 --speed
```
Output example:
```text
╭──────────── Ollama Host Report: http://127.0.0.1:11434 (v0.17.7) ────────────╮
│ ✔ Native Ollama API (/api/tags): 200 OK (1 models, 5.4ms)                    │
│ ✔ OpenAI REST API (/v1/models): 200 OK Compatible (1 models, 6.0ms)          │
│ ✔ Parity Check: Native models and OpenAI models match exactly.               │
│ ✔ REST Chat Speed (/v1/chat/completions): 4.5 tok/s (30 tokens in 9.34s,     │
│ TTFT: 2656ms) on cieloforge/qwen2.5-14B-instruct-spec:latest                 │
╰──────────────────────────────────────────────────────────────────────────────╯
                        OpenAI REST Chat Speed Benchmark                        
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ MODEL          ┃     SPEED ┃    TTFT ┃ TOTAL TIME ┃ TOKENS ┃ REPLY PREVIEW   ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ cieloforge/qw… │ 4.5 tok/s │ 2656 ms │     9.34 s │     30 │ The sky is blue │
│                │           │         │            │        │ because small   │
│                │           │         │            │        │ particl...      │
└────────────────┴───────────┴─────────┴────────────┴────────┴─────────────────┘
```

Customize the benchmark prompt or token count:
```bash
python3 ollama_cli.py 127.0.0.1 --speed --speed-prompt "Write a haiku." --speed-tokens 20
```

---

### 4. Basic Target Probe
Inspect endpoints and model metadata:
```bash
python3 ollama_cli.py 127.0.0.1
```

---

### 5. Advanced CLI Options

#### Call only Ollama native list (`/api/tags`)
```bash
python3 ollama_cli.py 192.168.1.100 --list
```

#### Test only OpenAI REST API (`/v1/models`)
```bash
python3 ollama_cli.py 192.168.1.100 --openai
```

#### Check Chat Authorization Only
```bash
python3 ollama_cli.py 192.168.1.100 --check-chat
# Or using positional syntax:
python3 ollama_cli.py auth 192.168.1.100
```

#### Custom Port and Timeout
```bash
python3 ollama_cli.py 192.168.1.100 --port 8080 --timeout 3.0
# Or directly include the port in the target (colon or space):
python3 ollama_cli.py 192.168.1.100:8080
python3 ollama_cli.py 192.168.1.100 8080
# Or configure default port via environment variables:
export OLLAMA_PORT=8080
python3 ollama_cli.py 192.168.1.100
```

#### Read IPs from file or stdin (e.g. Shodan sweeps)
```bash
python3 ollama_cli.py -f ips.txt --quiet --speed
cat ips.txt | python3 ollama_cli.py -f - --quiet
```

#### Scan an IP Range for Ollama (Port 11434 & /v1/models)
Scan a subnet or range of IP addresses to discover Ollama instances on port 11434 and test the OpenAI REST API (`/v1/models`). Supports CIDR notation, dash ranges, wildcards, and comma-separated lists:
```bash
# Scan CIDR range (e.g. 192.168.1.0/24 or /28):
python3 ollama_cli.py --range 192.168.1.0/24

# Scan start-to-end IP range:
python3 ollama_cli.py -r 192.168.1.1-192.168.1.50

# Scan abbreviated last-octet range:
python3 ollama_cli.py -r 192.168.1.1-50

# Scan wildcard range:
python3 ollama_cli.py -r 192.168.1.*

# Positional syntax (also auto-detects ranges):
python3 ollama_cli.py 192.168.1.0/24 --quiet

# Scan range testing ONLY OpenAI /v1/models (compact summary table):
python3 ollama_cli.py -r 192.168.1.0/24 -o --quiet

# Scan range with verbose live sliding ETA and DuckDB caching:
python3 ollama_cli.py -r 192.168.1.0/24 -v -db

# Multi-threaded concurrent range scanning (--threads / -T):
python3 ollama_cli.py -r 192.168.1.0/24 -T 20 --quiet
```

#### Multi-Host Scan with Verbose Progress & Sliding ETA
When scanning multiple targets (from file, stdin, or multiple command-line arguments), adding `-v` / `--verbose` displays live per-host progress, the specific IP processed, host duration, status badge, elapsed time, and a dynamic **sliding window ETA** (`Slide ETA`):
```bash
python3 ollama_cli.py -f ips.txt -v
# Or when sweeping directly from command-line targets:
python3 ollama_cli.py 192.168.1.10 192.168.1.20 192.168.1.30 -v
```
Progress output example:
```text
[*] Starting multi-host scan for 50 targets (verbose mode)...
[*] [1/50] (2.0%) Processed IP: 192.168.1.10 (0.18s) - [OK (OPEN), 2 models] | Elapsed: 00:00 | Slide ETA: 00:08 (0.18s/host)
[*] [2/50] (4.0%) Processed IP: 192.168.1.20 (0.42s) - [UNAUTHORIZED (HTTP 401)] | Elapsed: 00:00 | Slide ETA: 00:14 (0.30s/host)
[*] [3/50] (6.0%) Processed IP: 192.168.1.30 (2.01s) - [Failed: Connection refused] | Elapsed: 00:02 | Slide ETA: 00:40 (0.87s/host)
...
[*] Multi-host scan complete: 50 IPs processed in 00:38.
```

#### Output Machine-Readable JSON
```bash
python3 ollama_cli.py 127.0.0.1 --json
```

#### DuckDB Persistence, Caching & Re-checks (`-db`, `--force`, `--db-summary`, `--db-query`)
When `-db` (or `--db [PATH]`) is passed, `ollama_cli.py` stores target scan records and discovered models in a local [DuckDB](https://duckdb.org) database (defaulting to `ollama_targets.duckdb`):

- **Automatic Cache Checking**: Before issuing network probes against any IP/host (passed directly or in a file via `-f`), the tool checks DuckDB. If the IP was already scanned, it skips network requests, rehydrates the cached report, and tags it as `(cached in DB)`:
  ```bash
  # First run: probes network and memorizes results in DuckDB:
  python3 ollama_cli.py 127.0.0.1 -db

  # Second run: detects IP is already in DB, skips probe, returns cached data instantly:
  python3 ollama_cli.py 127.0.0.1 -db

  # Multi-host scan with caching:
  python3 ollama_cli.py -f ips.txt -db -v
  ```
- **Force Re-checking (`--force`)**: Bypass the database cache and force fresh network probing of all target IPs (single IP or targets from file), updating the database with new results:
  ```bash
  # Force re-scan single IP:
  python3 ollama_cli.py 127.0.0.1 -db --force

  # Force re-scan an entire file of IPs:
  python3 ollama_cli.py -f ips.txt -db --force -v
  ```
- **Custom Database Path**:
  ```bash
  python3 ollama_cli.py -f ips.txt -db scans_2026.duckdb
  ```
- **Database Statistics & Summary (`--db-summary`)**:
  View aggregated metrics (total targets scanned, open vs unauthorized hosts, distinct models discovered, top models ranked by popularity):
  ```bash
  python3 ollama_cli.py --db-summary
  python3 ollama_cli.py -db custom.duckdb --db-summary
  ```
- **Direct SQL Queries (`--db-query`)**:
  Query the DuckDB database directly with arbitrary SQL queries:
  ```bash
  # List all open / authorized hosts with discovered models:
  python3 ollama_cli.py --db-query "SELECT host, port, status, models_count FROM targets WHERE is_authorized = true"

  # Query models discovered across all targets:
  python3 ollama_cli.py --db-query "SELECT name, parameter_size, quantization, count(*) as hosts FROM models GROUP BY 1, 2, 3 ORDER BY hosts DESC"

  # Output query results in JSON format:
  python3 ollama_cli.py --db-query "SELECT host, port, models_list FROM targets" --json
  ```

---

## Web Dashboard (`web_dashboard.py` on Port 2000)

Explore, search, filter, and query all target scans and models stored in the DuckDB database from a web dashboard running on port 2000.

### Launching the Dashboard

#### Option A: Standalone Launcher
```bash
# Launch on default port 2000 with default database (ollama_targets.duckdb):
python3 web_dashboard.py

# Custom port or custom database file:
python3 web_dashboard.py --port 2000 --db custom_targets.duckdb --host 0.0.0.0
```

#### Option B: Via `ollama_cli.py`
```bash
# Launch dashboard directly from ollama_cli:
python3 ollama_cli.py --dashboard

# With custom port and database:
python3 ollama_cli.py --dashboard --dashboard-port 2000 -db scans.duckdb
```

Once started, open **`http://localhost:2000`** in your browser.

### Key Capabilities

1. **KPI Metric Cards**:
   - Total Scanned Targets, Authorized / Open Hosts, Unauthorized (401/403) Hosts, Partial Hosts, Total & Unique Models Discovered, Average Discovery Latency, and Max Inference Throughput (`tok/s`).
2. **Targets Explorer**:
   - Real-time search across target IP addresses, hostnames, statuses, discovered models, and error messages.
   - Filter by status pills: `All`, `Open / Authorized`, `Unauthorized`, `Partial / Mixed`, `Failed / Offline`, `With Models`, `With Speed`.
   - Filter by model name and port number.
   - Column sorting (`Scanned At`, `Host`, `Port`, `Models Count`, `Latency`, `Speed`).
   - Deep inspection modal showing detailed API breakdowns (`/api/tags`, `/v1/models`, `/api/chat`, `/v1/chat/completions`), model details, and formatted raw JSON report.
3. **Models Registry**:
   - Aggregated catalog of all models discovered across all targets.
   - Host popularity count and open host count per model.
   - Model parameter sizes (e.g. `8.0B`, `70B`), quantization format (e.g. `Q4_K_M`), architecture families, and sample hosts.
4. **DuckDB SQL Studio**:
   - Execute arbitrary SQL queries directly against the live DuckDB database in your browser.
   - Built-in query presets: `All Open Hosts`, `Model Popularity Ranking`, `Fastest Inference Hosts`, `Unauthorized Target Inventory`.
   - Export query results to CSV.
5. **Live Target Prober**:
   - Probe any IP/hostname on demand directly from the web interface.
   - Optionally run chat speed benchmarks or supply custom API keys.
   - Instantly saves and updates the target record in DuckDB.
6. **Data Export**:
   - Export filtered target lists as plain `IP:PORT` text files (ideal for feeding into `ollama_cli.py -f`), CSV spreadsheets, or JSON arrays.

### REST API Endpoints

The dashboard server exposes clean, zero-dependency REST endpoints:
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/stats` | `GET` | Aggregated dashboard KPI metrics and top 10 models |
| `/api/targets` | `GET` | Filtered, sorted, paginated target records (`q`, `status`, `model`, `port`, `page`, `page_size`) |
| `/api/targets/<target_id>` | `GET` | Deep detail for a specific target host or base URL with discovered models |
| `/api/models` | `GET` | Grouped or ungrouped model registry catalog (`q`, `grouped`, `page`) |
| `/api/query` | `POST` | Execute arbitrary SQL queries against DuckDB (`{"query": "SELECT..."}`) |
| `/api/probe` | `POST` | Probe an IP/host on-demand and upsert result into DuckDB |
| `/api/export` | `GET` | Download targets matching filters as `txt`, `csv`, or `json` |

---

## Shodan Search & IP Harvester CLI (`shodan_cli.py`)

A dedicated CLI to authenticate to Shodan via **web login** (username & password) or **API key**, search queries, paginate through results across multiple pages, and save or pipe resulting IP addresses.

### Features
- **Web Login Authentication**: Logs into `https://account.shodan.io/login` with username & password, manages session cookies, extracts CSRF token, and bypasses unauthenticated search filter restrictions (`port:11434`, etc.).
- **Automatic Account API Key Discovery**: Automatically retrieves the user's permanent API key from the account dashboard upon login.
- **Web Scraping & API Modes**:
  - Web scraping mode (`--web`): Scrapes `https://www.shodan.io/search?query=...&page=...` using the authenticated session.
  - REST API mode (`--api`): Queries `https://api.shodan.io/shodan/host/search`.
  - Auto mode: Uses API when credits are available, and seamlessly falls back to web scraping if API query credits are exhausted.
- **Pagination & Result Limiting**: Specify starting page (`-s / --start-page <N>`), cycle across pages (`-p / --pages <N>`), and limit total collected IPs (`-l / --limit <N>`).
- **Target Output Formatting**: Save IPs to file (`-o targets.txt`), format as `IP:PORT` (`-P / --with-port`), and deduplicate entries automatically.
- **Pipelining**: Pipe directly into `ollama_cli.py` for automated probing and benchmarking.

### Shodan CLI Usage Examples

#### 1. Web Login & Save IPs to File
```bash
# Prompt securely for password:
python3 shodan_cli.py "port:11434 Ollama" -u myuser -o ips.txt

# Or specify password on command line / environment variables:
python3 shodan_cli.py "port:11434" -u myuser -W mypass -p 3 -o ips.txt
export SHODAN_USERNAME=myuser SHODAN_PASSWORD=mypass
python3 shodan_cli.py "product:Ollama" -p 2 -o ips.txt
```

#### 2. Start Page Selection & Multi-Page Pagination
```bash
# Start scanning from page 3 and query 5 pages (pages 3, 4, 5, 6, 7):
python3 shodan_cli.py "port:11434" -u myuser --start-page 3 -p 5 -o targets.txt

# Query up to 5 pages from page 1, capping collection at 100 IPs:
python3 shodan_cli.py "port:11434" -u myuser -p 5 --limit 100 -o targets.txt
```

#### 3. Save as `IP:PORT` for Target Lists
```bash
python3 shodan_cli.py "port:11434" -u myuser -P -o targets.txt
```

#### 4. Pipe Harvested IPs Directly into Ollama Probe CLI
```bash
# Sweep Shodan and benchmark all discovered Ollama instances in real time:
python3 shodan_cli.py "port:11434" -u myuser -p 2 -q | python3 ollama_cli.py -f - --speed
```

#### 5. Check Shodan Account & Credit Overview
```bash
python3 shodan_cli.py --info -u myuser
python3 shodan_cli.py --info -k <SHODAN_API_KEY>
```

---

## Running Unit Tests

Run the complete test suites:
```bash
# Web Dashboard unit & integration tests (16 tests):
python3 test_web_dashboard.py -v

# Ollama & OpenAI Probe CLI tests (74 tests):
python3 test_ollama_cli.py -v

# Shodan CLI tests (web login, scraping, pagination, API fallback - 22 tests):
python3 test_shodan_cli.py -v
```
