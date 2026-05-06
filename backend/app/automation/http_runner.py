from typing import Any

import httpx


class HttpWorkflowRunner:
    async def run(self, workflow: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
        base_url = workflow.get("base_url", "")
        steps = workflow.get("steps", [])
        context: dict[str, Any] = {"input": inputs, "steps": {}}
        results = []

        async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
            for step in steps:
                step_id = step["id"]
                request = step["request"]
                method = request["method"]
                url = _join_url(base_url, request["path"])
                headers = _render_mapping(request.get("headers", {}), context)
                json_body = _render_value(request.get("json"), context)

                response = await client.request(method, url, headers=headers, json=json_body)
                body = _safe_json(response)
                context["steps"][step_id] = {
                    "status": response.status_code,
                    "body": body,
                    "headers": dict(response.headers),
                }
                results.append(
                    {
                        "id": step_id,
                        "status": response.status_code,
                        "ok": 200 <= response.status_code < 300,
                    }
                )

        return {"results": results, "context": context}


def _join_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def _render_mapping(values: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    return {key: _render_value(value, context) for key, value in values.items()}


def _render_value(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: _render_value(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [_render_value(item, context) for item in value]
    if isinstance(value, str) and value.startswith("{{") and value.endswith("}}"):
        return _resolve_expr(value[2:-2].strip(), context)
    return value


def _resolve_expr(expr: str, context: dict[str, Any]) -> Any:
    current: Any = context
    for part in expr.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(f"Cannot resolve template expression: {expr}")
        current = current[part]
    return current


def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text
