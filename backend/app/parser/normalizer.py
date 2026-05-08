from typing import Any
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field


class RedactionFinding(BaseModel):
    location: str
    key: str
    placeholder: str


class BodySchema(BaseModel):
    type: str
    fields: dict[str, Any] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)


class HttpExchange(BaseModel):
    method: str
    url: str
    path: str
    query: dict[str, list[str]] = Field(default_factory=dict)
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: Any = None
    status: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: Any = None
    timestamp: str | None = None
    source: str = "unknown"
    operation_id: str | None = None
    step_index: int | None = None
    initiator: str | None = None
    resource_type: str | None = None
    request_body_schema: BodySchema | None = None
    response_body_schema: BodySchema | None = None
    redaction_report: list[RedactionFinding] = Field(default_factory=list)
    secret_refs: dict[str, str] = Field(default_factory=dict)


def normalize_url(method: str, url: str, **kwargs: Any) -> HttpExchange:
    parsed = urlparse(url)
    return HttpExchange(
        method=method.upper(),
        url=url,
        path=parsed.path or "/",
        query=parse_qs(parsed.query),
        **kwargs,
    )
