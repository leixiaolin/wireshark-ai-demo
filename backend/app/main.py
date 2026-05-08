import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request

from app.analyzer.api_discovery import ApiDiscoveryAnalyzer
from app.analyzer.openapi_builder import OpenApiBuilder
from app.analyzer.schema_inference import infer_exchange_schemas
from app.automation.browser_runner import BrowserAuthRequest, BrowserWorkflowRequest, BrowserWorkflowRunner
from app.automation.http_runner import HttpWorkflowRunner
from app.capture.session_manager import CaptureSession, CaptureSessionManager
from app.capture.tshark_capture import CaptureRequest, TsharkCapture
from app.capture.wireshark_tools import CaptureInterface, WiresharkDiagnostics, WiresharkToolchain
from app.parser.har_parser import HarParser
from app.parser.normalizer import HttpExchange
from app.parser.pcap_parser import PcapAnalysisRequest, PcapAnalysisResult, PcapParser
from app.parser.redactor import TrafficRedactor
from app.recording.manager import RecordingManager, RecordingRecord, RecordingStartRequest, RecordingStatus
from app.secrets.vault import SessionSecretCreate, SessionSecretInfo, SessionSecretVault


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("app")

app = FastAPI(title="Wireshark AI API Discovery Demo")

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
PCAP_DIR = DATA_DIR / "pcaps"
BROWSER_ARTIFACT_DIR = DATA_DIR / "browser"
RECORDING_DIR = DATA_DIR / "recordings"
SECRETS_DIR = DATA_DIR / "secrets"
TOOLCHAIN = WiresharkToolchain()
SESSION_MANAGER = CaptureSessionManager(output_dir=PCAP_DIR)
VAULT = SessionSecretVault(SECRETS_DIR)
RECORDINGS = RecordingManager(RECORDING_DIR, VAULT)


@app.middleware("http")
async def log_requests(request: Request, call_next: Any) -> Any:
    logger.info("request start method=%s path=%s", request.method, request.url.path)
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("request failed method=%s path=%s", request.method, request.url.path)
        raise
    logger.info("request done method=%s path=%s status=%s", request.method, request.url.path, response.status_code)
    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/capture/start")
def start_capture(request: CaptureRequest) -> dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    capture = TsharkCapture(output_dir=PCAP_DIR)
    return capture.build_command(request).model_dump()


@app.get("/capture/diagnostics")
def capture_diagnostics() -> WiresharkDiagnostics:
    return TOOLCHAIN.diagnose()


@app.get("/capture/interfaces")
def capture_interfaces() -> list[CaptureInterface]:
    try:
        return TOOLCHAIN.list_interfaces()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/capture/session/start")
def start_capture_session(request: CaptureRequest) -> CaptureSession:
    try:
        return SESSION_MANAGER.start(request)
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Failed to start capture: {exc}") from exc


@app.get("/capture/session")
def list_capture_sessions() -> list[CaptureSession]:
    return SESSION_MANAGER.list()


@app.get("/capture/session/{session_id}")
def get_capture_session(session_id: str) -> CaptureSession:
    try:
        return SESSION_MANAGER.get(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/capture/session/{session_id}/stop")
def stop_capture_session(session_id: str) -> CaptureSession:
    try:
        return SESSION_MANAGER.stop(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/capture/open-wireshark")
def open_wireshark(payload: dict[str, str]) -> dict[str, str]:
    pcap_path = Path(payload.get("pcap_path", ""))
    if not pcap_path.exists() or not pcap_path.is_file():
        raise HTTPException(status_code=404, detail="pcap_path not found")
    try:
        TOOLCHAIN.open_in_wireshark(pcap_path)
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Failed to open Wireshark: {exc}") from exc
    return {"status": "opened", "pcap_path": str(pcap_path)}


@app.post("/parse/har")
def parse_har(payload: dict[str, Any]) -> list[HttpExchange]:
    if "log" not in payload:
        raise HTTPException(status_code=400, detail="Expected a HAR object with a log field")
    return HarParser().parse(payload)


@app.post("/parse/pcap/analyze")
def analyze_pcap(request: PcapAnalysisRequest) -> PcapAnalysisResult:
    try:
        return PcapParser(TOOLCHAIN).analyze(request)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/parse/pcap/http-exchanges")
def parse_pcap_http_exchanges(request: PcapAnalysisRequest) -> list[HttpExchange]:
    try:
        return PcapParser(TOOLCHAIN).to_http_exchanges(request)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/analyze/exchanges")
def analyze_exchanges(exchanges: list[HttpExchange]) -> dict[str, Any]:
    redacted = TrafficRedactor().redact_many([infer_exchange_schemas(exchange) for exchange in exchanges])
    return ApiDiscoveryAnalyzer().analyze(redacted).model_dump()


@app.post("/openapi")
def build_openapi(exchanges: list[HttpExchange]) -> dict[str, Any]:
    redacted = TrafficRedactor().redact_many([infer_exchange_schemas(exchange) for exchange in exchanges])
    result = ApiDiscoveryAnalyzer().analyze(redacted)
    return OpenApiBuilder().build(result)


@app.post("/workflow/run")
async def run_workflow(payload: dict[str, Any]) -> dict[str, Any]:
    workflow = payload.get("workflow")
    inputs = payload.get("inputs", {})
    if not isinstance(workflow, dict):
        raise HTTPException(status_code=400, detail="workflow must be an object")
    try:
        return await HttpWorkflowRunner(VAULT).run(workflow, inputs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/browser/auth/save")
async def save_browser_auth(request: BrowserAuthRequest) -> dict[str, str]:
    try:
        logger.info("browser auth endpoint state_path=%s url=%s", request.state_path, request.url)
        return await BrowserWorkflowRunner(BROWSER_ARTIFACT_DIR, VAULT).save_auth_state(request)
    except Exception as exc:
        logger.exception("browser auth endpoint failed")
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/browser/workflow/run")
async def run_browser_workflow(request: BrowserWorkflowRequest) -> dict[str, Any]:
    try:
        logger.info("browser workflow endpoint steps=%s", len(request.workflow.get("steps", [])))
        return (await BrowserWorkflowRunner(BROWSER_ARTIFACT_DIR, VAULT).run(request.workflow, request.inputs)).model_dump()
    except Exception as exc:
        logger.exception("browser workflow endpoint failed")
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/recording/start")
async def start_recording(request: RecordingStartRequest) -> RecordingStatus:
    try:
        return await RECORDINGS.start(request)
    except Exception as exc:
        logger.exception("recording start failed")
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/recording/{recording_id}/stop")
async def stop_recording(recording_id: str) -> RecordingRecord:
    try:
        return await RECORDINGS.stop(recording_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("recording stop failed")
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/recording/{recording_id}")
def get_recording(recording_id: str) -> RecordingRecord:
    try:
        return RECORDINGS.get(recording_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/recording/{recording_id}/analyze")
def analyze_recording(recording_id: str) -> dict[str, Any]:
    try:
        return RECORDINGS.analyze(recording_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/recording/{recording_id}/apis")
def recording_apis(recording_id: str) -> dict[str, Any]:
    try:
        return RECORDINGS.apis(recording_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/recording/{recording_id}/openapi")
def recording_openapi(recording_id: str) -> dict[str, Any]:
    try:
        result = ApiDiscoveryAnalyzer().analyze(RECORDINGS.get(recording_id).redacted_exchanges)
        return OpenApiBuilder().build(result)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/recording/{recording_id}/workflow/browser")
def recording_browser_workflow(recording_id: str) -> dict[str, Any]:
    try:
        return RECORDINGS.browser_workflow(recording_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/recording/{recording_id}/workflow/http")
def recording_http_workflow(recording_id: str) -> dict[str, Any]:
    try:
        return RECORDINGS.http_workflow(recording_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/secrets/session")
def create_session_secret(request: SessionSecretCreate) -> SessionSecretInfo:
    return VAULT.create(request)


@app.get("/secrets/session")
def list_session_secrets() -> list[SessionSecretInfo]:
    return VAULT.list()


@app.delete("/secrets/session/{secret_id}")
def delete_session_secret(secret_id: str) -> dict[str, str]:
    try:
        VAULT.delete(secret_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "deleted", "id": secret_id}
