import re
from typing import Any

from app.parser.normalizer import HttpExchange, RedactionFinding


SECRET_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "x-xsrf-token",
    "token",
    "access_token",
    "refresh_token",
    "password",
    "passwd",
    "pwd",
    "csrf",
    "xsrf",
}

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
ID_CARD_RE = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")


class TrafficRedactor:
    def redact_exchange(self, exchange: HttpExchange) -> HttpExchange:
        data = exchange.model_dump()
        findings: list[RedactionFinding] = []
        secret_refs: dict[str, str] = dict(data.get("secret_refs") or {})
        data["request_headers"] = _redact_mapping(data["request_headers"], "request.headers", findings, secret_refs)
        data["response_headers"] = _redact_mapping(data["response_headers"], "response.headers", findings, secret_refs)
        data["request_body"] = _redact_value(data["request_body"], "request.body", findings, secret_refs)
        data["response_body"] = _redact_value(data["response_body"], "response.body", findings, secret_refs)
        data["redaction_report"] = findings
        data["secret_refs"] = secret_refs
        return HttpExchange(**data)

    def redact_many(self, exchanges: list[HttpExchange]) -> list[HttpExchange]:
        return [self.redact_exchange(exchange) for exchange in exchanges]


def _redact_mapping(
    values: dict[str, Any],
    location: str,
    findings: list[RedactionFinding],
    secret_refs: dict[str, str],
) -> dict[str, Any]:
    return {
        key: _placeholder(location, key, findings, secret_refs)
        if _is_secret_key(key)
        else _redact_value(value, f"{location}.{key}", findings, secret_refs)
        for key, value in values.items()
    }


def _redact_value(
    value: Any,
    location: str,
    findings: list[RedactionFinding],
    secret_refs: dict[str, str],
) -> Any:
    if isinstance(value, dict):
        return {
            key: _placeholder(location, key, findings, secret_refs)
            if _is_secret_key(key)
            else _redact_value(item, f"{location}.{key}", findings, secret_refs)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item, f"{location}[]", findings, secret_refs) for item in value]
    if isinstance(value, str):
        value = EMAIL_RE.sub("[EMAIL]", value)
        value = PHONE_RE.sub("[PHONE]", value)
        value = ID_CARD_RE.sub("[ID_CARD]", value)
    return value


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in SECRET_KEYS or "token" in lowered or "secret" in lowered


def _placeholder(
    location: str,
    key: str,
    findings: list[RedactionFinding],
    secret_refs: dict[str, str],
) -> str:
    normalized = key.lower().replace("-", "_")
    if "cookie" in normalized:
        placeholder = "{{secrets.session.cookie}}"
    elif "authorization" in normalized:
        placeholder = "{{secrets.session.authorization}}"
    elif "csrf" in normalized or "xsrf" in normalized:
        placeholder = "{{secrets.session.csrf_token}}"
    elif "password" in normalized or normalized in {"passwd", "pwd"}:
        placeholder = "{{secrets.session.password_not_saved}}"
    else:
        placeholder = f"{{{{secrets.session.{normalized}}}}}"
    findings.append(RedactionFinding(location=location, key=key, placeholder=placeholder))
    secret_refs[f"{location}.{key}"] = placeholder
    return placeholder
