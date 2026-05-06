from typing import Any
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, Field


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


def normalize_url(method: str, url: str, **kwargs: Any) -> HttpExchange:
    parsed = urlparse(url)
    return HttpExchange(
        method=method.upper(),
        url=url,
        path=parsed.path or "/",
        query=parse_qs(parsed.query),
        **kwargs,
    )
