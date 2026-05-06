from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException

from app.analyzer.api_discovery import ApiDiscoveryAnalyzer
from app.analyzer.openapi_builder import OpenApiBuilder
from app.automation.http_runner import HttpWorkflowRunner
from app.capture.tshark_capture import CaptureRequest, TsharkCapture
from app.parser.har_parser import HarParser
from app.parser.normalizer import HttpExchange
from app.parser.redactor import TrafficRedactor


app = FastAPI(title="Wireshark AI API Discovery Demo")

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/capture/start")
def start_capture(request: CaptureRequest) -> dict[str, Any]:
    capture = TsharkCapture(output_dir=DATA_DIR / "pcaps")
    return capture.build_command(request).model_dump()


@app.post("/parse/har")
def parse_har(payload: dict[str, Any]) -> list[HttpExchange]:
    if "log" not in payload:
        raise HTTPException(status_code=400, detail="Expected a HAR object with a log field")
    return HarParser().parse(payload)


@app.post("/analyze/exchanges")
def analyze_exchanges(exchanges: list[HttpExchange]) -> dict[str, Any]:
    redacted = TrafficRedactor().redact_many(exchanges)
    return ApiDiscoveryAnalyzer().analyze(redacted).model_dump()


@app.post("/openapi")
def build_openapi(exchanges: list[HttpExchange]) -> dict[str, Any]:
    redacted = TrafficRedactor().redact_many(exchanges)
    result = ApiDiscoveryAnalyzer().analyze(redacted)
    return OpenApiBuilder().build(result)


@app.post("/workflow/run")
async def run_workflow(payload: dict[str, Any]) -> dict[str, Any]:
    workflow = payload.get("workflow")
    inputs = payload.get("inputs", {})
    if not isinstance(workflow, dict):
        raise HTTPException(status_code=400, detail="workflow must be an object")
    return await HttpWorkflowRunner().run(workflow, inputs)
