import re
from collections import defaultdict
from typing import Any

from pydantic import BaseModel, Field

from app.parser.normalizer import HttpExchange


SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-csrf-token", "x-xsrf-token"}


class ApiEndpoint(BaseModel):
    method: str
    path_template: str
    samples: int
    statuses: list[int] = Field(default_factory=list)
    request_content_types: list[str] = Field(default_factory=list)
    response_content_types: list[str] = Field(default_factory=list)
    auth_signals: list[str] = Field(default_factory=list)


class ApiDiscoveryResult(BaseModel):
    endpoints: list[ApiEndpoint]
    sequence: list[str]
    warnings: list[str]


class ApiDiscoveryAnalyzer:
    def analyze(self, exchanges: list[HttpExchange]) -> ApiDiscoveryResult:
        grouped: dict[tuple[str, str], list[HttpExchange]] = defaultdict(list)
        sequence: list[str] = []

        for exchange in exchanges:
            template = _template_path(exchange.path)
            key = (exchange.method, template)
            grouped[key].append(exchange)
            sequence.append(f"{exchange.method} {template}")

        endpoints = [
            self._endpoint(method, template, samples)
            for (method, template), samples in sorted(grouped.items())
        ]

        warnings = [
            "Only observed traffic can be reported. Untriggered APIs cannot be proven from packet capture.",
            "Replay may fail when requests depend on CSRF tokens, nonces, browser fingerprints, or server-side state.",
        ]

        return ApiDiscoveryResult(endpoints=endpoints, sequence=sequence, warnings=warnings)

    def _endpoint(self, method: str, template: str, samples: list[HttpExchange]) -> ApiEndpoint:
        statuses = sorted({sample.status for sample in samples if sample.status is not None})
        request_types = sorted(
            {
                sample.request_headers.get("content-type", "").split(";")[0]
                for sample in samples
                if sample.request_headers.get("content-type")
            }
        )
        response_types = sorted(
            {
                sample.response_headers.get("content-type", "").split(";")[0]
                for sample in samples
                if sample.response_headers.get("content-type")
            }
        )
        auth_signals = sorted(
            {
                header
                for sample in samples
                for header in sample.request_headers
                if header in SENSITIVE_HEADERS
            }
        )
        return ApiEndpoint(
            method=method,
            path_template=template,
            samples=len(samples),
            statuses=statuses,
            request_content_types=request_types,
            response_content_types=response_types,
            auth_signals=auth_signals,
        )


def _template_path(path: str) -> str:
    parts = []
    for part in path.strip("/").split("/"):
        if re.fullmatch(r"\d+", part):
            parts.append("{id}")
        elif re.fullmatch(r"[0-9a-fA-F-]{16,}", part):
            parts.append("{token}")
        else:
            parts.append(part)
    return "/" + "/".join(parts) if parts and parts != [""] else "/"
