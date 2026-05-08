from typing import Any
from urllib.parse import urlparse

import httpx

from app.automation.templating import render_mapping, render_value
from app.secrets.vault import SessionSecretVault


class HttpWorkflowRunner:
    def __init__(self, vault: SessionSecretVault | None = None) -> None:
        self.vault = vault

    async def run(self, workflow: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
        base_url = workflow.get("base_url", "")
        steps = workflow.get("steps", [])
        dry_run = bool(workflow.get("dry_run", False))
        allowed_domains = workflow.get("allowed_domains", [])
        confirm_write = bool(workflow.get("confirm_write", False))
        unattended = bool(workflow.get("unattended", False))
        _validate_workflow_controls(base_url, steps, allowed_domains, confirm_write, unattended, dry_run)
        context: dict[str, Any] = {"input": inputs, "steps": {}}
        results = []
        secret_headers = self._secret_headers(workflow.get("auth_secret_ref"), allowed_domains)

        async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
            for step in steps:
                step_id = step["id"]
                request = step["request"]
                method = request["method"]
                url = _join_url(base_url, request["path"])
                headers = render_mapping(request.get("headers", {}), context)
                headers.update(secret_headers)
                json_body = render_value(request.get("json"), context)
                params = render_mapping(request.get("query", {}), context)
                data = render_value(request.get("data"), context)

                if dry_run:
                    results.append({"id": step_id, "status": None, "ok": True, "dry_run": True, "url": url})
                    continue

                response = await client.request(method, url, headers=headers, params=params, json=json_body, data=data)
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

    def _secret_headers(self, auth_secret_ref: str | None, allowed_domains: list[str]) -> dict[str, str]:
        if not auth_secret_ref or self.vault is None:
            return {}
        secret_id = _secret_id(auth_secret_ref)
        data = self.vault.read_data(secret_id)
        headers = data.get("headers", {})
        if isinstance(headers, dict) and headers:
            return {str(key): str(value) for key, value in headers.items()}
        storage_state = data.get("storage_state", {})
        cookies = storage_state.get("cookies", []) if isinstance(storage_state, dict) else []
        cookie_header = _cookie_header(cookies, allowed_domains)
        if cookie_header:
            return {"cookie": cookie_header}
        return {}


def _join_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return base_url.rstrip("/") + "/" + path.lstrip("/")

def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text


def _validate_workflow_controls(
    base_url: str,
    steps: list[dict[str, Any]],
    allowed_domains: list[str],
    confirm_write: bool,
    unattended: bool,
    dry_run: bool,
) -> None:
    if not allowed_domains:
        raise ValueError("allowed_domains is required before workflow execution")
    for step in steps:
        request = step.get("request", {})
        method = str(request.get("method", "GET")).upper()
        url = _join_url(base_url, str(request.get("path", "")))
        host = urlparse(url).netloc
        if host not in allowed_domains:
            raise ValueError(f"Workflow target is outside allowed_domains: {host}")
        if method in {"POST", "PUT", "PATCH", "DELETE"} and not dry_run and not (confirm_write or unattended):
            raise ValueError(f"Write step requires confirm_write or unattended=true: {step.get('id')}")
    if unattended and not allowed_domains:
        raise ValueError("unattended workflows require allowed_domains")


def _secret_id(secret_ref: str) -> str:
    value = secret_ref.strip()
    if value.startswith("{{") and value.endswith("}}"):
        value = value[2:-2].strip()
    return value.split(".")[-1]


def _cookie_header(cookies: Any, allowed_domains: list[str]) -> str:
    if not isinstance(cookies, list):
        return ""
    pairs = []
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        domain = str(cookie.get("domain", "")).lstrip(".")
        if allowed_domains and domain and not any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowed_domains):
            continue
        name = cookie.get("name")
        value = cookie.get("value")
        if name is not None and value is not None:
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)
