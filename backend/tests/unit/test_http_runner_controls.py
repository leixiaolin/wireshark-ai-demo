import asyncio

import pytest

from app.automation.http_runner import HttpWorkflowRunner
from app.secrets.vault import SessionSecretVault


def test_http_runner_requires_allowed_domains() -> None:
    workflow = {
        "base_url": "https://example.com",
        "steps": [{"id": "submit", "request": {"method": "POST", "path": "/api/posts"}}],
        "dry_run": True,
    }

    with pytest.raises(ValueError, match="allowed_domains"):
        asyncio.run(HttpWorkflowRunner().run(workflow, {}))


def test_http_runner_dry_run_without_network_for_allowed_domain() -> None:
    workflow = {
        "base_url": "https://example.com",
        "allowed_domains": ["example.com"],
        "dry_run": True,
        "steps": [{"id": "submit", "request": {"method": "POST", "path": "/api/posts"}}],
    }

    result = asyncio.run(HttpWorkflowRunner().run(workflow, {}))

    assert result["results"] == [
        {
            "id": "submit",
            "status": None,
            "ok": True,
            "dry_run": True,
            "url": "https://example.com/api/posts",
        }
    ]


def test_http_runner_requires_confirm_for_live_write() -> None:
    workflow = {
        "base_url": "https://example.com",
        "allowed_domains": ["example.com"],
        "steps": [{"id": "submit", "request": {"method": "POST", "path": "/api/posts"}}],
    }

    with pytest.raises(ValueError, match="confirm_write"):
        asyncio.run(HttpWorkflowRunner().run(workflow, {}))


def test_http_runner_builds_cookie_header_from_storage_state(tmp_path) -> None:
    vault = SessionSecretVault(tmp_path)
    info = vault.save_data(
        name="example",
        data={
            "storage_state": {
                "cookies": [
                    {"domain": "example.com", "name": "sid", "value": "secret"},
                    {"domain": "other.com", "name": "ignored", "value": "x"},
                ]
            }
        },
    )

    headers = HttpWorkflowRunner(vault)._secret_headers(f"{{{{secrets.session.{info.id}}}}}", ["example.com"])

    assert headers == {"cookie": "sid=secret"}
