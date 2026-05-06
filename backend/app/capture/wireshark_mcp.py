from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field


class McpCaptureSession(BaseModel):
    session_id: str
    status: str
    artifact_path: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class WiresharkMcpClient(Protocol):
    async def start_capture(self, interface: str, capture_filter: str | None = None) -> McpCaptureSession:
        ...

    async def stop_capture(self, session_id: str) -> McpCaptureSession:
        ...

    async def export_pcap(self, session_id: str, output_dir: Path) -> Path:
        ...


class PlaceholderWiresharkMcpClient:
    async def start_capture(self, interface: str, capture_filter: str | None = None) -> McpCaptureSession:
        raise NotImplementedError("Connect this adapter to the actual wireshark-mcp tool.")

    async def stop_capture(self, session_id: str) -> McpCaptureSession:
        raise NotImplementedError("Connect this adapter to the actual wireshark-mcp tool.")

    async def export_pcap(self, session_id: str, output_dir: Path) -> Path:
        raise NotImplementedError("Connect this adapter to the actual wireshark-mcp tool.")
