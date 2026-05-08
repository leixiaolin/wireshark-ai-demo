import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.analyzer.api_discovery import ApiDiscoveryAnalyzer
from app.analyzer.schema_inference import infer_exchange_schemas
from app.automation.browser_runner import _load_playwright
from app.parser.normalizer import HttpExchange, normalize_url
from app.parser.redactor import TrafficRedactor
from app.secrets.vault import SessionSecretInfo, SessionSecretVault


class RecordingStartRequest(BaseModel):
    url: str
    name: str | None = None
    headless: bool = False
    allowed_domains: list[str] = Field(default_factory=list)
    wait_until_stop: bool = True


class RecordingStatus(BaseModel):
    id: str
    name: str
    status: str
    url: str
    allowed_domains: list[str]
    started_at: str
    stopped_at: str | None = None
    secret_ref: str | None = None
    exchange_count: int = 0
    warnings: list[str] = Field(default_factory=list)


class RecordingRecord(BaseModel):
    status: RecordingStatus
    exchanges: list[HttpExchange] = Field(default_factory=list)
    redacted_exchanges: list[HttpExchange] = Field(default_factory=list)
    screenshots: list[str] = Field(default_factory=list)
    analysis: dict[str, Any] | None = None


class _ActiveRecording(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    status: RecordingStatus
    browser: Any
    context: Any
    page: Any
    responses: list[Any] = Field(default_factory=list)


class RecordingManager:
    def __init__(self, root_dir: Path, vault: SessionSecretVault) -> None:
        self.root_dir = root_dir
        self.vault = vault
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._active: dict[str, _ActiveRecording] = {}
        self._playwright_context: Any = None

    async def start(self, request: RecordingStartRequest) -> RecordingStatus:
        playwright = _load_playwright()
        if self._playwright_context is None:
            self._playwright_context = await playwright().start()
        browser = await self._playwright_context.chromium.launch(headless=request.headless)
        context = await browser.new_context()
        page = await context.new_page()

        recording_id = uuid4().hex
        domains = request.allowed_domains or [_host(request.url)]
        status = RecordingStatus(
            id=recording_id,
            name=request.name or f"recording-{recording_id[:8]}",
            status="running",
            url=request.url,
            allowed_domains=[domain for domain in domains if domain],
            started_at=_now(),
            warnings=[
                "Only APIs observed during this recording can be reported.",
                "Captcha, rate-limit, anti-abuse, and access-control bypass are intentionally unsupported.",
            ],
        )
        active = _ActiveRecording(status=status, browser=browser, context=context, page=page)
        page.on("response", lambda response: active.responses.append(response))
        self._active[recording_id] = active
        await page.goto(request.url)
        self._write_record(RecordingRecord(status=status))
        return status

    async def stop(self, recording_id: str) -> RecordingRecord:
        active = self._active.pop(recording_id, None)
        if active is None:
            record = self.get(recording_id)
            return record

        raw_exchanges = await self._responses_to_exchanges(recording_id, active.responses)
        exchanges = [infer_exchange_schemas(exchange) for exchange in raw_exchanges]
        redacted = TrafficRedactor().redact_many(exchanges)
        screenshot_path = self._dir(recording_id) / "final.png"
        screenshot_path.parent.mkdir(parents=True, exist_ok=True)
        await active.page.screenshot(path=str(screenshot_path), full_page=True)
        storage_state = await active.context.storage_state()
        secret_info = self.vault.save_data(
            name=active.status.name,
            kind="playwright_storage_state",
            allowed_domains=active.status.allowed_domains,
            data={"storage_state": storage_state},
        )
        await active.browser.close()

        status = active.status.model_copy(
            update={
                "status": "stopped",
                "stopped_at": _now(),
                "secret_ref": f"{{{{secrets.session.{secret_info.id}}}}}",
                "exchange_count": len(redacted),
            }
        )
        record = RecordingRecord(
            status=status,
            exchanges=exchanges,
            redacted_exchanges=redacted,
            screenshots=[str(screenshot_path)],
        )
        self._write_record(record)
        return record

    def get(self, recording_id: str) -> RecordingRecord:
        path = self._record_path(recording_id)
        if not path.exists():
            raise KeyError(f"Unknown recording: {recording_id}")
        return RecordingRecord(**json.loads(path.read_text(encoding="utf-8")))

    def analyze(self, recording_id: str) -> dict[str, Any]:
        record = self.get(recording_id)
        discovery = ApiDiscoveryAnalyzer().analyze(record.redacted_exchanges).model_dump()
        analysis = {
            "recording_id": recording_id,
            "input_policy": "redacted_summary_only",
            "api_discovery": discovery,
            "ai_draft": _local_ai_draft(record.redacted_exchanges),
        }
        updated = record.model_copy(update={"analysis": analysis})
        self._write_record(updated)
        return analysis

    def apis(self, recording_id: str) -> dict[str, Any]:
        record = self.get(recording_id)
        return ApiDiscoveryAnalyzer().analyze(record.redacted_exchanges).model_dump()

    def browser_workflow(self, recording_id: str) -> dict[str, Any]:
        record = self.get(recording_id)
        return {
            "base_url": _origin(record.status.url),
            "auth_secret_ref": record.status.secret_ref,
            "allowed_domains": record.status.allowed_domains,
            "headless": True,
            "unattended": False,
            "confirm_write": True,
            "steps": [
                {"id": "open_recorded_start", "type": "goto", "url": record.status.url},
                {"id": "evidence", "type": "screenshot", "name": f"{record.status.id}-replay.png"},
            ],
        }

    def http_workflow(self, recording_id: str) -> dict[str, Any]:
        record = self.get(recording_id)
        steps = []
        for index, exchange in enumerate(record.redacted_exchanges):
            if exchange.resource_type and exchange.resource_type not in {"xhr", "fetch", "document"}:
                continue
            steps.append(
                {
                    "id": f"step_{index + 1}",
                    "request": {
                        "method": exchange.method,
                        "path": exchange.path,
                        "headers": _safe_replay_headers(exchange.request_headers),
                        "json": exchange.request_body if isinstance(exchange.request_body, dict) else None,
                    },
                    "requires_review": exchange.method in {"POST", "PUT", "PATCH", "DELETE"},
                }
            )
        return {
            "base_url": _origin(record.status.url),
            "allowed_domains": record.status.allowed_domains,
            "dry_run": True,
            "confirm_write": True,
            "unattended": False,
            "auth_secret_ref": record.status.secret_ref,
            "steps": steps,
        }

    async def _responses_to_exchanges(self, recording_id: str, responses: list[Any]) -> list[HttpExchange]:
        exchanges = []
        for index, response in enumerate(responses):
            request = response.request
            headers = await request.all_headers()
            request_body = request.post_data
            response_headers = dict(response.headers)
            response_body = await _response_preview(response)
            exchanges.append(
                normalize_url(
                    request.method,
                    response.url,
                    request_headers={key.lower(): value for key, value in headers.items()},
                    request_body=request_body,
                    status=response.status,
                    response_headers={key.lower(): value for key, value in response_headers.items()},
                    response_body=response_body,
                    source="playwright",
                    operation_id=recording_id,
                    step_index=index + 1,
                    initiator=request.frame.url if request.frame else None,
                    resource_type=request.resource_type,
                )
            )
        return exchanges

    def _write_record(self, record: RecordingRecord) -> None:
        path = self._record_path(record.status.id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(record.model_dump_json(indent=2), encoding="utf-8")

    def _dir(self, recording_id: str) -> Path:
        return self.root_dir / recording_id

    def _record_path(self, recording_id: str) -> Path:
        return self._dir(recording_id) / "recording.json"


async def _response_preview(response: Any, limit: int = 100_000) -> Any:
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return await response.json()
        except Exception:
            return None
    try:
        text = await response.text()
    except Exception:
        return None
    return text[:limit]


def _local_ai_draft(exchanges: list[HttpExchange]) -> dict[str, Any]:
    return {
        "status": "draft_without_remote_model",
        "policy": "Remote AI integration must receive only this redacted payload.",
        "operations": [
            {
                "method": exchange.method,
                "path": exchange.path,
                "purpose_guess": "submit_or_mutate" if exchange.method in {"POST", "PUT", "PATCH", "DELETE"} else "read_or_lookup",
                "risk": "review_required" if exchange.method in {"POST", "PUT", "PATCH", "DELETE"} else "low",
                "dynamic_inputs": sorted(exchange.secret_refs.values()),
            }
            for exchange in exchanges
        ],
    }


def _safe_replay_headers(headers: dict[str, str]) -> dict[str, str]:
    allowed = {"content-type", "accept", "x-requested-with"}
    return {key: value for key, value in headers.items() if key.lower() in allowed}


def _host(url: str) -> str:
    return urlparse(url).netloc


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
