import logging
from pathlib import Path
from time import time
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.automation.templating import render_value


logger = logging.getLogger("app.browser")


class BrowserWorkflowRequest(BaseModel):
    workflow: dict[str, Any]
    inputs: dict[str, Any] = Field(default_factory=dict)


class BrowserAuthRequest(BaseModel):
    url: str
    state_path: str
    headless: bool = False
    wait_seconds: int = Field(default=120, ge=1, le=1800)
    save_when_url_contains: str | None = None
    save_when_selector: str | None = None


class BrowserStepResult(BaseModel):
    id: str
    type: str
    ok: bool
    detail: str | None = None


class BrowserNetworkRecord(BaseModel):
    method: str
    url: str
    status: int | None = None
    resource_type: str | None = None
    content_type: str | None = None


class BrowserWorkflowResult(BaseModel):
    results: list[BrowserStepResult]
    network: list[BrowserNetworkRecord]
    screenshots: list[str]
    auth_state_path: str | None = None


class BrowserWorkflowRunner:
    def __init__(self, artifact_dir: Path) -> None:
        self.artifact_dir = artifact_dir

    async def save_auth_state(self, request: BrowserAuthRequest) -> dict[str, str]:
        playwright = _load_playwright()
        state_path = Path(request.state_path)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(
            "browser auth save requested url=%s state_path=%s headless=%s wait_seconds=%s",
            request.url,
            state_path,
            request.headless,
            request.wait_seconds,
        )

        async with playwright() as p:
            browser = await p.chromium.launch(headless=request.headless)
            context = await browser.new_context()
            page = await context.new_page()
            logger.info("browser auth navigating to %s", request.url)
            await page.goto(request.url)
            await self._wait_for_auth_completion(page, request)
            logger.info("browser auth saving storage_state to %s", state_path)
            await context.storage_state(path=str(state_path))
            await browser.close()
            logger.info("browser auth saved state_path=%s exists=%s", state_path, state_path.exists())

        return {"status": "saved", "state_path": str(state_path)}

    async def run(self, workflow: dict[str, Any], inputs: dict[str, Any]) -> BrowserWorkflowResult:
        playwright = _load_playwright()
        context_data: dict[str, Any] = {"input": inputs, "steps": {}}
        results: list[BrowserStepResult] = []
        network: list[BrowserNetworkRecord] = []
        screenshots: list[str] = []

        base_url = workflow.get("base_url", "")
        headless = bool(workflow.get("headless", True))
        timeout_ms = int(workflow.get("timeout_ms", 30000))
        auth_state = workflow.get("auth_state")
        save_auth_state = workflow.get("save_auth_state")

        async with playwright() as p:
            logger.info(
                "browser workflow starting steps=%s headless=%s auth_state=%s",
                len(workflow.get("steps", [])),
                headless,
                auth_state,
            )
            browser = await p.chromium.launch(headless=headless)
            browser_context_kwargs: dict[str, Any] = {}
            if auth_state:
                browser_context_kwargs["storage_state"] = str(auth_state)
            browser_context = await browser.new_context(**browser_context_kwargs)
            browser_context.set_default_timeout(timeout_ms)
            page = await browser_context.new_page()

            page.on("response", lambda response: network.append(_network_record(response)))

            for index, step in enumerate(workflow.get("steps", [])):
                step_id = str(step.get("id") or f"step_{index + 1}")
                step_type = str(step.get("type", ""))
                logger.info("browser workflow step start id=%s type=%s", step_id, step_type)
                try:
                    detail = await self._run_step(page, base_url, step, context_data, screenshots)
                    context_data["steps"][step_id] = {"ok": True, "detail": detail}
                    results.append(BrowserStepResult(id=step_id, type=step_type, ok=True, detail=detail))
                    logger.info("browser workflow step ok id=%s type=%s detail=%s", step_id, step_type, detail)
                except Exception as exc:
                    context_data["steps"][step_id] = {"ok": False, "detail": str(exc)}
                    results.append(BrowserStepResult(id=step_id, type=step_type, ok=False, detail=str(exc)))
                    logger.exception("browser workflow step failed id=%s type=%s", step_id, step_type)
                    if not step.get("continue_on_error", False):
                        break

            if save_auth_state:
                state_path = Path(str(save_auth_state))
                state_path.parent.mkdir(parents=True, exist_ok=True)
                await browser_context.storage_state(path=str(state_path))
                auth_state_path = str(state_path)
                logger.info("browser workflow saved auth_state_path=%s", auth_state_path)
            else:
                auth_state_path = None

            await browser.close()
            logger.info(
                "browser workflow finished ok_steps=%s total_steps=%s network_records=%s screenshots=%s",
                sum(1 for result in results if result.ok),
                len(results),
                len(network),
                len(screenshots),
            )

        return BrowserWorkflowResult(
            results=results,
            network=network,
            screenshots=screenshots,
            auth_state_path=auth_state_path,
        )

    async def _run_step(
        self,
        page: Any,
        base_url: str,
        step: dict[str, Any],
        context: dict[str, Any],
        screenshots: list[str],
    ) -> str | None:
        step_type: Literal[
            "goto",
            "fill",
            "click",
            "select",
            "check",
            "uncheck",
            "wait_for_url",
            "wait_for_selector",
            "expect_text",
            "screenshot",
            "wait",
        ] = step["type"]

        if step_type == "goto":
            url = _join_url(base_url, str(render_value(step["url"], context)))
            await page.goto(url)
            return url
        if step_type == "fill":
            await page.locator(step["selector"]).fill(str(render_value(step.get("value", ""), context)))
            return step["selector"]
        if step_type == "click":
            await page.locator(step["selector"]).click()
            return step["selector"]
        if step_type == "select":
            value = render_value(step.get("value"), context)
            await page.locator(step["selector"]).select_option(value)
            return step["selector"]
        if step_type == "check":
            await page.locator(step["selector"]).check()
            return step["selector"]
        if step_type == "uncheck":
            await page.locator(step["selector"]).uncheck()
            return step["selector"]
        if step_type == "wait_for_url":
            await page.wait_for_url(str(render_value(step["url"], context)))
            return step["url"]
        if step_type == "wait_for_selector":
            await page.wait_for_selector(step["selector"])
            return step["selector"]
        if step_type == "expect_text":
            await page.get_by_text(str(render_value(step["text"], context))).wait_for()
            return step["text"]
        if step_type == "screenshot":
            path = self._screenshot_path(str(step.get("name") or f"screenshot-{int(time())}.png"))
            await page.screenshot(path=str(path), full_page=bool(step.get("full_page", True)))
            screenshots.append(str(path))
            return str(path)
        if step_type == "wait":
            await page.wait_for_timeout(int(step.get("milliseconds", 1000)))
            return str(step.get("milliseconds", 1000))

        raise ValueError(f"Unsupported browser workflow step type: {step_type}")

    def _screenshot_path(self, name: str) -> Path:
        safe_name = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in name)
        path = self.artifact_dir / safe_name
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    async def _wait_for_auth_completion(self, page: Any, request: BrowserAuthRequest) -> None:
        timeout_ms = request.wait_seconds * 1000
        if request.save_when_selector:
            logger.info("browser auth waiting for selector=%s", request.save_when_selector)
            try:
                await page.wait_for_selector(request.save_when_selector, timeout=timeout_ms)
                logger.info("browser auth selector matched selector=%s", request.save_when_selector)
                return
            except Exception:
                logger.exception("browser auth selector wait timed out; saving current browser state anyway")
                return

        if request.save_when_url_contains:
            logger.info("browser auth waiting for url containing=%s", request.save_when_url_contains)
            deadline = time() + request.wait_seconds
            while time() < deadline:
                if request.save_when_url_contains in page.url:
                    logger.info("browser auth url matched current_url=%s", page.url)
                    return
                await page.wait_for_timeout(1000)
            logger.warning("browser auth url wait timed out current_url=%s; saving current browser state anyway", page.url)
            return

        logger.info("browser auth waiting fixed seconds=%s before saving state", request.wait_seconds)
        await page.wait_for_timeout(timeout_ms)


def _load_playwright() -> Any:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright is not installed. Run: pip install playwright") from exc
    return async_playwright


def _join_url(base_url: str, path: str) -> str:
    if path.startswith(("http://", "https://", "data:", "file:", "about:")):
        return path
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def _network_record(response: Any) -> BrowserNetworkRecord:
    request = response.request
    return BrowserNetworkRecord(
        method=request.method,
        url=response.url,
        status=response.status,
        resource_type=request.resource_type,
        content_type=response.headers.get("content-type"),
    )
