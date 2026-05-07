# Wireshark AI API Discovery Demo

This repository is an MVP scaffold for the workflow:

```text
record one authorized web business operation
  -> extract observed HTTP APIs
  -> analyze traffic with AI-assisted rules
  -> generate an API catalog and workflow draft
  -> replay stable operations with automation
```

The goal is not to bypass closed-source application protections. Use it only for systems and accounts where you have authorization to test, observe, and automate.

## Architecture

```text
browser operation
  -> wireshark/tshark, wireshark-mcp, or HAR capture
  -> normalized HTTP exchanges
  -> redaction
  -> API discovery / schema inference / workflow inference
  -> OpenAPI draft and automation workflow
  -> HTTP runner or Playwright runner
```

## Included

- FastAPI backend
- tshark capture command builder
- wireshark-mcp adapter placeholder
- HAR parser
- sensitive data redactor
- normalized HTTP exchange model
- API endpoint clustering
- OpenAPI 3.1 draft builder
- simple HTTP workflow runner

## Start

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\uvicorn app.main:app --reload
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

## Recommended capture paths

### Path 1: Browser HAR

HAR is the easiest first input for web API analysis.

Post the HAR JSON to:

```text
POST /parse/har
POST /analyze/exchanges
POST /openapi
```

### Path 2: Wireshark/tshark + SSLKEYLOGFILE

Set the key log file before launching the browser:

```powershell
$env:SSLKEYLOGFILE="D:\cursor_workspace\wireshark-ai-demo\data\sslkeys.log"
Start-Process chrome.exe
```

Then call:

```text
POST /capture/start
```

Example body:

```json
{
  "interface": "Wi-Fi",
  "host": "example.com",
  "duration_seconds": 120,
  "ssl_keylog_file": "D:\\cursor_workspace\\wireshark-ai-demo\\data\\sslkeys.log"
}
```

The endpoint returns the suggested `tshark` command. Replace this with real wireshark-mcp calls when the MCP tool is available.

## wireshark-mcp integration point

The placeholder lives here:

```text
backend/app/capture/wireshark_mcp.py
```

Expected MCP capabilities:

- `start_capture(interface, filter)`
- `stop_capture(session_id)`
- `export_pcap(session_id)`

If the MCP server can return HTTP transactions directly, convert them into `HttpExchange` and skip pcap parsing.

## Local Wireshark workflow

The backend can now drive the local Wireshark CLI toolchain directly. The stable automation path is `tshark`/`dumpcap`
for capture and analysis, with the Wireshark desktop UI used only as an optional viewer for saved `.pcapng` files.

Useful endpoints:

```text
GET  /capture/diagnostics
GET  /capture/interfaces
POST /capture/session/start
GET  /capture/session
GET  /capture/session/{session_id}
POST /capture/session/{session_id}/stop
POST /capture/open-wireshark
POST /parse/pcap/analyze
POST /parse/pcap/http-exchanges
```

If `tshark -D` cannot list interfaces on Windows, start or repair Npcap with administrator privileges before attempting
live capture. HTTPS API extraction from pcap requires browser TLS key logging via `SSLKEYLOGFILE`; without it, use HAR
capture or expect only DNS/TLS metadata.

## Workflow example

```json
{
  "workflow": {
    "base_url": "https://example.com",
    "steps": [
      {
        "id": "submit",
        "request": {
          "method": "POST",
          "path": "/api/form/submit",
          "headers": {
            "content-type": "application/json"
          },
          "json": {
            "title": "{{input.title}}",
            "content": "{{input.content}}"
          }
        }
      }
    ]
  },
  "inputs": {
    "title": "demo",
    "content": "hello"
  }
}
```

Post it to:

```text
POST /workflow/run
```

## Browser automation workflow

For campus workflows such as leave requests, entry reporting, or other stateful web forms, prefer Playwright browser
automation first. It keeps the real browser login/session/CSRF behavior intact, then records network responses as
supporting evidence.

Install browser binaries after installing Python dependencies:

```powershell
cd backend
.\venv\Scripts\python -m playwright install chromium
```

Save login state once:

```text
POST /browser/auth/save
```

Example body:

```json
{
  "url": "https://example.edu/login",
  "state_path": "E:\\cursor_workspace\\wireshark-ai-demo\\data\\auth\\campus.json",
  "headless": false,
  "wait_seconds": 120,
  "save_when_url_contains": "example.edu"
}
```

During the wait window, log in manually in the opened browser. The backend saves the authenticated browser state when
the timer ends.

For QR-code login flows such as CSDN, use a URL condition so the state is saved soon after the login redirect:

```json
{
  "url": "https://passport.csdn.net/login",
  "state_path": "E:\\cursor_workspace\\wireshark-ai-demo\\data\\auth\\csdn.json",
  "headless": false,
  "wait_seconds": 300,
  "save_when_url_contains": "www.csdn.net"
}
```

Run a browser workflow:

```text
POST /browser/workflow/run
```

Example:

```json
{
  "workflow": {
    "base_url": "https://example.edu",
    "auth_state": "E:\\cursor_workspace\\wireshark-ai-demo\\data\\auth\\campus.json",
    "headless": false,
    "steps": [
      {"id": "open", "type": "goto", "url": "/leave/apply"},
      {"id": "start", "type": "fill", "selector": "input[name='startDate']", "value": "{{input.start_date}}"},
      {"id": "reason", "type": "fill", "selector": "textarea[name='reason']", "value": "{{input.reason}}"},
      {"id": "submit", "type": "click", "selector": "button[type='submit']"},
      {"id": "success", "type": "expect_text", "text": "提交成功"},
      {"id": "shot", "type": "screenshot", "name": "leave-success.png"}
    ]
  },
  "inputs": {
    "start_date": "2026-05-08",
    "reason": "demo"
  }
}
```

After a workflow is reliable in the browser, stable non-interactive API calls can be moved to `POST /workflow/run`.

## Next implementation steps

1. Wire `PlaceholderWiresharkMcpClient` to the actual wireshark-mcp tool.
2. Add pcapng parsing via `tshark -r file.pcapng -T json`.
3. Expand schema inference for JSON request and response bodies.
4. Add a Playwright runner for CSRF, dynamic signatures, and browser-dependent flows.
5. Add a frontend for capture sessions, API catalog review, and workflow editing.
