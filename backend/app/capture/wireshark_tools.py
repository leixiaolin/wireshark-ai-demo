import os
import re
import subprocess
from pathlib import Path
from shutil import which
from typing import Any

from pydantic import BaseModel, Field


DEFAULT_WINDOWS_TOOL_DIRS = (
    Path("C:/Program Files/Wireshark"),
    Path("C:/Program Files (x86)/Wireshark"),
    Path("d:/Program Files/Wireshark"),
)


class CommandResult(BaseModel):
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


class WiresharkToolStatus(BaseModel):
    name: str
    path: str | None
    available: bool


class CaptureInterface(BaseModel):
    index: str
    name: str
    description: str | None = None


class WiresharkDiagnostics(BaseModel):
    tools: dict[str, WiresharkToolStatus]
    interfaces: list[CaptureInterface] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class WiresharkToolchain:
    def __init__(self) -> None:
        self.tshark_path = discover_wireshark_tool("tshark")
        self.dumpcap_path = discover_wireshark_tool("dumpcap")
        self.wireshark_path = discover_wireshark_tool("wireshark")
        self.capinfos_path = discover_wireshark_tool("capinfos")

    def run(self, command: list[str], timeout: int = 60) -> CommandResult:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return CommandResult(
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def list_interfaces(self) -> list[CaptureInterface]:
        result = self.run([self.tshark_path, "-D"], timeout=30)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Failed to list interfaces")
        return parse_interfaces(result.stdout)

    def diagnose(self) -> WiresharkDiagnostics:
        tools = {
            "tshark": _status("tshark", self.tshark_path),
            "dumpcap": _status("dumpcap", self.dumpcap_path),
            "wireshark": _status("wireshark", self.wireshark_path),
            "capinfos": _status("capinfos", self.capinfos_path),
        }
        warnings: list[str] = []
        interfaces: list[CaptureInterface] = []

        try:
            interfaces = self.list_interfaces()
        except Exception as exc:
            warnings.append(
                "Unable to list capture interfaces. On Windows this usually means Npcap is stopped, "
                f"missing, or requires administrator privileges. Detail: {exc}"
            )

        return WiresharkDiagnostics(tools=tools, interfaces=interfaces, warnings=warnings)

    def open_in_wireshark(self, pcap_path: Path) -> None:
        subprocess.Popen([self.wireshark_path, str(pcap_path)])


def discover_wireshark_tool(name: str) -> str:
    exe = f"{name}.exe" if os.name == "nt" and not name.endswith(".exe") else name
    env_key = f"WIRESHARK_MCP_{name.upper()}_PATH"
    configured = os.getenv(env_key)
    if configured and Path(configured).exists():
        return configured

    resolved = which(name) or which(exe)
    if resolved:
        return resolved

    for directory in DEFAULT_WINDOWS_TOOL_DIRS:
        candidate = directory / exe
        if candidate.exists():
            return str(candidate)

    return name


def parse_interfaces(output: str) -> list[CaptureInterface]:
    interfaces: list[CaptureInterface] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\.\s+(.+?)(?:\s+\((.+)\))?\s*$", line)
        if not match:
            continue
        interfaces.append(
            CaptureInterface(
                index=match.group(1),
                name=match.group(2),
                description=match.group(3),
            )
        )
    return interfaces


def _status(name: str, path: str) -> WiresharkToolStatus:
    return WiresharkToolStatus(name=name, path=path, available=Path(path).exists() or which(path) is not None)
