import re
from typing import Any

from app.parser.normalizer import HttpExchange


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
}

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")


class TrafficRedactor:
    def redact_exchange(self, exchange: HttpExchange) -> HttpExchange:
        data = exchange.model_dump()
        data["request_headers"] = _redact_mapping(data["request_headers"])
        data["response_headers"] = _redact_mapping(data["response_headers"])
        data["request_body"] = _redact_value(data["request_body"])
        data["response_body"] = _redact_value(data["response_body"])
        return HttpExchange(**data)

    def redact_many(self, exchanges: list[HttpExchange]) -> list[HttpExchange]:
        return [self.redact_exchange(exchange) for exchange in exchanges]


def _redact_mapping(values: dict[str, Any]) -> dict[str, Any]:
    return {
        key: "[REDACTED]" if key.lower() in SECRET_KEYS else _redact_value(value)
        for key, value in values.items()
    }


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SECRET_KEYS else _redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        value = EMAIL_RE.sub("[EMAIL]", value)
        value = PHONE_RE.sub("[PHONE]", value)
    return value
