from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.capture.wireshark_tools import WiresharkToolchain
from app.parser.normalizer import HttpExchange, normalize_url


class PcapAnalysisRequest(BaseModel):
    pcap_path: str
    ssl_keylog_file: str | None = None
    limit: int = Field(default=200, ge=1, le=5000)


class PcapAnalysisResult(BaseModel):
    pcap_path: str
    http: list[dict[str, str]]
    http2: list[dict[str, str]]
    dns: list[dict[str, str]]
    tls_sni: list[dict[str, str]]
    warnings: list[str] = Field(default_factory=list)


class PcapParser:
    def __init__(self, toolchain: WiresharkToolchain | None = None) -> None:
        self.toolchain = toolchain or WiresharkToolchain()

    def analyze(self, request: PcapAnalysisRequest) -> PcapAnalysisResult:
        pcap_path = Path(request.pcap_path)
        _ensure_file(pcap_path)

        warnings: list[str] = []
        http = self._extract(
            pcap_path,
            [
                "frame.number",
                "frame.time_epoch",
                "ip.src",
                "ip.dst",
                "tcp.stream",
                "http.request.method",
                "http.host",
                "http.request.uri",
                "http.response.code",
                "http.content_type",
            ],
            "http",
            request.limit,
            request.ssl_keylog_file,
        )
        http2 = self._extract(
            pcap_path,
            [
                "frame.number",
                "frame.time_epoch",
                "ip.src",
                "ip.dst",
                "tcp.stream",
                "http2.headers.method",
                "http2.headers.scheme",
                "http2.headers.authority",
                "http2.headers.path",
                "http2.headers.status",
            ],
            "http2",
            request.limit,
            request.ssl_keylog_file,
        )
        dns = self._extract(
            pcap_path,
            ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "dns.qry.name", "dns.qry.type"],
            "dns.qry.name",
            request.limit,
            request.ssl_keylog_file,
        )
        tls_sni = self._extract(
            pcap_path,
            ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tls.handshake.extensions_server_name"],
            "tls.handshake.extensions_server_name",
            request.limit,
            request.ssl_keylog_file,
        )

        if not http and not http2:
            warnings.append(
                "No decoded HTTP/HTTP2 records were found. For HTTPS traffic, provide a browser SSLKEYLOGFILE "
                "or capture browser-level HAR when TLS decryption is unavailable."
            )

        return PcapAnalysisResult(
            pcap_path=str(pcap_path),
            http=http,
            http2=http2,
            dns=dns,
            tls_sni=tls_sni,
            warnings=warnings,
        )

    def to_http_exchanges(self, request: PcapAnalysisRequest) -> list[HttpExchange]:
        result = self.analyze(request)
        exchanges: list[HttpExchange] = []
        for row in result.http:
            method = row.get("http.request.method")
            host = row.get("http.host")
            uri = row.get("http.request.uri")
            if not method or not host or not uri:
                continue

            scheme = "https" if row.get("tls.handshake.extensions_server_name") else "http"
            url = uri if uri.startswith(("http://", "https://")) else f"{scheme}://{host}{uri}"
            exchanges.append(
                normalize_url(
                    method,
                    url,
                    request_headers={"host": host},
                    status=_safe_int(row.get("http.response.code")),
                    response_headers=_content_type_header(row.get("http.content_type")),
                    timestamp=row.get("frame.time_epoch") or None,
                    source="pcap",
                )
            )
        for row in result.http2:
            method = row.get("http2.headers.method")
            scheme = row.get("http2.headers.scheme") or "https"
            host = row.get("http2.headers.authority")
            path = row.get("http2.headers.path")
            if not method or not host or not path:
                continue
            exchanges.append(
                normalize_url(
                    method,
                    f"{scheme}://{host}{path}",
                    request_headers={"host": host},
                    status=_safe_int(row.get("http2.headers.status")),
                    timestamp=row.get("frame.time_epoch") or None,
                    source="pcap",
                )
            )
        return exchanges

    def _extract(
        self,
        pcap_path: Path,
        fields: list[str],
        display_filter: str,
        limit: int,
        ssl_keylog_file: str | None,
    ) -> list[dict[str, str]]:
        command = [self.toolchain.tshark_path, "-r", str(pcap_path)]
        if ssl_keylog_file:
            command.extend(["-o", f"tls.keylog_file:{ssl_keylog_file}"])
        command.extend(
            [
                "-Y",
                display_filter,
                "-T",
                "fields",
                "-E",
                "header=y",
                "-E",
                "separator=\t",
                "-E",
                "occurrence=f",
            ]
        )
        for field in fields:
            command.extend(["-e", field])

        result = self.toolchain.run(command, timeout=120)
        if result.returncode != 0:
            return []
        return _parse_tsv(result.stdout, limit)


def _parse_tsv(output: str, limit: int) -> list[dict[str, str]]:
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) < 2:
        return []

    headers = lines[0].split("\t")
    rows: list[dict[str, str]] = []
    for line in lines[1 : limit + 1]:
        values = line.split("\t")
        rows.append({header: values[index] if index < len(values) else "" for index, header in enumerate(headers)})
    return rows


def _ensure_file(path: Path) -> None:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"pcap file not found: {path}")


def _safe_int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _content_type_header(value: str | None) -> dict[str, str]:
    return {"content-type": value} if value else {}
