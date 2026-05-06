from typing import Any

from app.analyzer.api_discovery import ApiDiscoveryResult


class OpenApiBuilder:
    def build(self, result: ApiDiscoveryResult, title: str = "Discovered API") -> dict[str, Any]:
        paths: dict[str, Any] = {}
        for endpoint in result.endpoints:
            path_item = paths.setdefault(endpoint.path_template, {})
            path_item[endpoint.method.lower()] = {
                "summary": f"Observed {endpoint.method} {endpoint.path_template}",
                "responses": _responses(endpoint.statuses),
                "x-observed-samples": endpoint.samples,
                "x-auth-signals": endpoint.auth_signals,
            }
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
