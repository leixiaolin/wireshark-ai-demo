from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class CaptureRequest(BaseModel):
    interface: str = Field(..., description="Network interface name or index for tshark")
    host: str | None = Field(default=None, description="Optional host capture filter")
    duration_seconds: int = Field(default=120, ge=1, le=3600)
    ssl_keylog_file: str | None = Field(
        default=None,
        description="Path to browser SSLKEYLOGFILE for TLS decryption",
    )
    output_name: str | None = None


class CaptureCommand(BaseModel):
    mode: Literal["manual_command"] = "manual_command"
    pcap_path: str
    command: list[str]
    notes: list[str]


class TsharkCapture:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def build_command(self, request: CaptureRequest) -> CaptureCommand:
        name = request.output_name or f"session-{uuid4().hex[:10]}.pcapng"
        pcap_path = self.output_dir / name

        command = [
            "tshark",
            "-i",
            request.interface,
            "-a",
            f"duration:{request.duration_seconds}",
            "-w",
            str(pcap_path),
        ]

        if request.host:
            command.extend(["-f", f"host {request.host}"])

        notes = [
            "Run the browser with SSLKEYLOGFILE set before starting capture.",
            "Configure Wireshark/tshark TLS preferences to use the same key log file when decoding.",
        ]
        if request.ssl_keylog_file:
            notes.append(f"TLS key log file: {request.ssl_keylog_file}")

        return CaptureCommand(pcap_path=str(pcap_path), command=command, notes=notes)
