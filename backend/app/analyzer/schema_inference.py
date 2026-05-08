import json
from typing import Any
from urllib.parse import parse_qs

from app.parser.normalizer import BodySchema, HttpExchange


def infer_exchange_schemas(exchange: HttpExchange) -> HttpExchange:
    return exchange.model_copy(
        update={
            "request_body_schema": infer_schema(exchange.request_body, exchange.request_headers),
            "response_body_schema": infer_schema(exchange.response_body, exchange.response_headers),
        }
    )


def infer_schema(value: Any, headers: dict[str, str] | None = None) -> BodySchema | None:
    if value is None or value == "":
        return None
    parsed = _parse_body(value, headers or {})
    return BodySchema(type=_type_name(parsed), fields=_fields(parsed), required=_required(parsed))


def _parse_body(value: Any, headers: dict[str, str]) -> Any:
    if not isinstance(value, str):
        return value
    content_type = headers.get("content-type", "").split(";")[0]
    if content_type == "application/json" or value.strip().startswith(("{", "[")):
        try:
            return json.loads(value)
        except ValueError:
            return value
    if content_type == "application/x-www-form-urlencoded":
        return {key: vals[0] if len(vals) == 1 else vals for key, vals in parse_qs(value).items()}
    return value


def _fields(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {str(key): _describe(item) for key, item in value.items()}
    if isinstance(value, list) and value:
        return {"items": _describe(value[0])}
    return {}


def _required(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    return [str(key) for key, item in value.items() if item is not None and item != ""]


def _describe(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"type": "object", "fields": _fields(value), "required": _required(value)}
    if isinstance(value, list):
        return {"type": "array", "items": _describe(value[0]) if value else {"type": "unknown"}}
    return {"type": _type_name(value)}


def _type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if value is None:
        return "null"
    return "string"
