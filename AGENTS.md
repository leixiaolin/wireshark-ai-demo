# Agent Guide - Wireshark AI API Discovery Demo

## Project Overview

MVP for automated API discovery and workflow automation. Records authorized web operations, extracts observed HTTP APIs, analyzes traffic with AI-assisted rules, generates an API catalog (OpenAPI 3.1), and replays stable operations via HTTP or Playwright browser automation.

Core pipeline:

```text
Browser operation
  -> Playwright recording, HAR input, or Wireshark/tshark capture
  -> Normalized HTTP exchanges
  -> Redaction of sensitive data
  -> API discovery / schema inference
  -> OpenAPI 3.1 draft + automation workflow
  -> HTTP runner or Playwright runner
```

## Tech Stack

- **Runtime**: Python 3.10+
- **Framework**: FastAPI 0.136 + Uvicorn (ASGI)
- **Validation**: Pydantic v2
- **Network capture**: tshark / dumpcap / Wireshark CLI tools, wireshark-mcp (placeholder)
- **Browser automation**: Playwright (Chromium)
- **HTTP client**: httpx
- **Security**: cryptography (Fernet-based secret vault)
- **Testing**: pytest

## Directory Structure

```text
wireshark-ai-demo/
|-- backend/
|   |-- app/
|   |   |-- main.py              # FastAPI app, all route definitions
|   |   |-- analyzer/            # API clustering, schema inference, OpenAPI builder
|   |   |-- automation/          # HTTP workflow runner, Playwright browser runner
|   |   |-- capture/             # tshark capture, session manager, wireshark-mcp placeholder
|   |   |-- parser/              # HAR parser, PCAP parser, normalizer, redactor
|   |   |-- recording/           # Recording lifecycle and artifact generation
|   |   `-- secrets/             # Encrypted session secret vault
|   |-- requirements.txt
|   `-- tests/
|       |-- conftest.py
|       `-- unit/
`-- data/                        # Runtime data (pcaps, browser artifacts, secrets, recordings)
```

## Build & Run

```bash
cd backend
python -m venv venv

# Windows:
venv\Scripts\pip install -r requirements.txt
venv\Scripts\python -m playwright install chromium
venv\Scripts\uvicorn app.main:app --reload

# Health check:
# GET http://127.0.0.1:8000/health
```

## Testing

```bash
cd backend
venv\Scripts\python -m pytest tests/ -v
```

Tests live in `backend/tests/unit/`. Use pytest fixtures from `conftest.py`.

## API Route Map

| Prefix | Module | Purpose |
|---|---|---|
| `GET /health` | `main.py` | Liveness check |
| `/capture/*` | `capture/` | tshark capture sessions, diagnostics, interface listing |
| `/parse/*` | `parser/` | HAR parsing, PCAP analysis, HTTP exchange extraction |
| `/analyze/*`, `/openapi` | `analyzer/` | Exchange analysis, OpenAPI 3.1 generation |
| `/workflow/run` | `automation/http_runner` | HTTP workflow replay |
| `/browser/*` | `automation/browser_runner` | Playwright auth save + browser workflow |
| `/recording/*` | `recording/` | Recording start/stop/analyze/workflow generation |
| `/secrets/*` | `secrets/` | Session secret vault CRUD |

## Code Conventions

- **Python style**: PEP 8, type hints on all function signatures, Pydantic models for request/response schemas.
- **No separate routers**: all routes are defined in `main.py`. When adding routes, define the route function in `main.py` and keep logic in the corresponding module.
- **Pydantic models**: request/response models live in the module that owns the logic, such as `CaptureRequest` in `capture/tshark_capture.py`.
- **Path handling**: use `pathlib.Path` for all file paths. Resolve runtime artifacts relative to `DATA_DIR` (`<project_root>/data/`).
- **Error handling**: convert domain exceptions (`KeyError`, `OSError`, `FileNotFoundError`, `ValueError`) into `HTTPException` at the API boundary.
- **Logging**: use `logging.getLogger(__name__)`; root logging config is set in `main.py`.
- **No ORM / database**: all state is in-memory or file-based (pcap files, JSON artifacts, encrypted vault files).

## Response Requirements

- For development tasks that are not pure Q&A, final responses must include `本轮完成度:X%`.
- In that same closeout, state whether the main goal for the current turn is complete, what was verified, what gaps remain, and the next concrete step.
- For roadmap work, long-running tasks, or multi-stage main goals, also include `整体目标完成度:Y%`.
- When reporting overall progress, explain the percentage basis, such as implementation coverage, verified workflows, or remaining planned stages.
- Pure Q&A answers do not need completion percentages unless they also include code changes, file edits, commits, or other development work.

## Key Data Flow

1. **HttpExchange** (`parser/normalizer.py`) is the central normalized HTTP request/response model.
2. **TrafficRedactor** (`parser/redactor.py`) scrubs sensitive headers, cookies, tokens, passwords, and common personal data before analysis output.
3. **ApiDiscoveryAnalyzer** (`analyzer/api_discovery.py`) clusters exchanges by path pattern and infers endpoint groups, operation type, replay risk, and dependencies.
4. **OpenApiBuilder** (`analyzer/openapi_builder.py`) converts analysis results into an OpenAPI 3.1 spec.
5. **RecordingManager** (`recording/manager.py`) orchestrates Playwright recording by listening to request/response events, extracting exchanges directly, redacting them, saving encrypted browser storage state, and generating analysis/workflow artifacts.

## Security Model

- `allowed_domains` is required for browser and HTTP workflow execution and is always enforced.
- `dry_run` mode previews steps without executing HTTP requests or browser actions.
- `confirm_write` or `unattended` is required for non-dry-run HTTP write methods (`POST`, `PUT`, `PATCH`, `DELETE`).
- **Redaction** strips authorization headers, cookies, CSRF tokens, passwords, and token-like fields from analysis output.
- **Session vault** (`secrets/vault.py`) encrypts secrets at rest using Fernet from the `cryptography` library.
- Passwords are never saved by the recorder; use post-login browser state instead.
- The project is intended for authorized systems and accounts only. It does not implement captcha bypass, anti-abuse bypass, or access-control bypass.

## Common Tasks

### Add a new API endpoint

1. Define request/response Pydantic models in the relevant module under `app/`.
2. Add the route function in `main.py` following existing patterns.
3. Keep business logic in the module, not in `main.py`.

### Add a new parser or capture source

1. Create a parser in `app/parser/` that produces `list[HttpExchange]`.
2. Feed the result into the existing analysis pipeline (`/analyze/exchanges`, `/openapi`).

### Add new test coverage

1. Add test files in `backend/tests/unit/`.
2. Use `conftest.py` for shared fixtures.
3. Run with `pytest tests/ -v`.

## Important Notes

- The `PlaceholderWiresharkMcpClient` in `capture/wireshark_mcp.py` is a stub; it needs to be connected to the real wireshark-mcp tool before MCP capture is functional.
- On Windows, tshark may not list interfaces if Npcap is not installed or not running with the required privileges.
- HTTPS API extraction from PCAP requires `SSLKEYLOGFILE` to be set before browser launch; without it, use Playwright recording or HAR input instead.
- The project currently uses `backend/venv/` for the virtual environment directory.
