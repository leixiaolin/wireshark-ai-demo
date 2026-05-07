import subprocess
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel

from app.capture.tshark_capture import CaptureRequest, TsharkCapture


class CaptureSession(BaseModel):
    session_id: str
    status: str
    pcap_path: str
    command: list[str]
    returncode: int | None = None
    stderr_tail: str | None = None


class CaptureSessionManager:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self._processes: dict[str, subprocess.Popen[str]] = {}
        self._sessions: dict[str, CaptureSession] = {}

    def start(self, request: CaptureRequest) -> CaptureSession:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if not request.output_name:
            request = request.model_copy(update={"output_name": f"session-{uuid4().hex[:10]}.pcapng"})

        command = TsharkCapture(self.output_dir).build_command(request)
        process = subprocess.Popen(
            command.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        session_id = uuid4().hex
        session = CaptureSession(
            session_id=session_id,
            status="running",
            pcap_path=command.pcap_path,
            command=command.command,
        )
        self._processes[session_id] = process
        self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> CaptureSession:
        session = self._require_session(session_id)
        process = self._processes.get(session_id)
        if process is None:
            return session

        returncode = process.poll()
        if returncode is None:
            return session

        _, stderr = process.communicate(timeout=1)
        updated = session.model_copy(
            update={
                "status": "completed" if returncode == 0 else "failed",
                "returncode": returncode,
                "stderr_tail": _tail(stderr),
            }
        )
        self._sessions[session_id] = updated
        self._processes.pop(session_id, None)
        return updated

    def stop(self, session_id: str) -> CaptureSession:
        session = self._require_session(session_id)
        process = self._processes.get(session_id)
        if process is None:
            return session

        process.terminate()
        try:
            _, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            _, stderr = process.communicate(timeout=10)

        updated = session.model_copy(
            update={
                "status": "stopped" if process.returncode == 0 else "failed",
                "returncode": process.returncode,
                "stderr_tail": _tail(stderr),
            }
        )
        self._sessions[session_id] = updated
        self._processes.pop(session_id, None)
        return updated

    def list(self) -> list[CaptureSession]:
        return [self.get(session_id) for session_id in list(self._sessions)]

    def _require_session(self, session_id: str) -> CaptureSession:
        if session_id not in self._sessions:
            raise KeyError(f"Unknown capture session: {session_id}")
        return self._sessions[session_id]


def _tail(value: str, lines: int = 20) -> str | None:
    if not value:
        return None
    return "\n".join(value.splitlines()[-lines:])
