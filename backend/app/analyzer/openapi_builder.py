from typing import Any

from app.analyzer.api_discovery import ApiDiscoveryResult


class OpenApiBuilder:
    def build(self, result: ApiDiscoveryResult, title: str = "Discovered API") -> dict[str, Any]:
        paths: dict[str, Any] = {}
        for endpoint in result.endpoints:
            path_item = paths.setdefault(endpoint.path_template, {})
            operation = {
                "summary": f"Observed {endpoint.method} {endpoint.path_template}",
                "parameters": _query_parameters(endpoint.query_schema),
                "responses": _responses(endpoint.statuses),
                "x-observed-samples": endpoint.samples,
                "x-auth-signals": endpoint.auth_signals,
                "x-operation-type": endpoint.operation_type,
                "x-replay-risk": endpoint.replay_risk,
                "x-dependencies": endpoint.dependencies,
            }
            request_body = _request_body(endpoint.request_body_schema)
            if request_body:
                operation["requestBody"] = request_body
            path_item[endpoint.method.lower()] = operation
        return {
            "openapi": "3.1.0",
            "info": {"title": title, "version": "0.1.0"},
            "paths": paths,
            "x-warnings": result.warnings,
        }


def _responses(statuses: list[int]) -> dict[str, Any]:
    if not statuses:
        return {"default": {"description": "Observed response"}}
    return {str(status): {"description": f"Observed HTTP {status}"} for status in statuses}


def _query_parameters(schema: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "in": "query",
            "required": False,
            "schema": {"type": value},
        }
        for name, value in schema.items()
    ]


def _request_body(schema: dict[str, Any] | None) -> dict[str, Any] | None:
    if not schema:
        return None
    return {
        "required": bool(schema.get("required")),
        "content": {
            "application/json": {
                "schema": _body_schema(schema),
            }
        },
    }


def _body_schema(schema: dict[str, Any]) -> dict[str, Any]:
    properties = {}
    for name, field in (schema.get("fields") or {}).items():
        properties[name] = {"type": field.get("type", "string")}
    return {
        "type": schema.get("type", "object"),
        "properties": properties,
        "required": schema.get("required", []),
    }
