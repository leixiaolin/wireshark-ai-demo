from typing import Any

from app.parser.normalizer import HttpExchange, normalize_url


class HarParser:
    def parse(self, har: dict[str, Any]) -> list[HttpExchange]:
        entries = har.get("log", {}).get("entries", [])
        exchanges: list[HttpExchange] = []

        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})
            url = request.get("url")
            method = request.get("method")
            if not url or not method:
                continue

            exchanges.append(
                normalize_url(
                    method=method,
                    url=url,
                    request_headers=_headers(request.get("headers", [])),
                    request_body=_post_data(request.get("postData")),
                    status=response.get("status"),
                    response_headers=_headers(response.get("headers", [])),
                    response_body=_content(response.get("content", {})),
                    timestamp=entry.get("startedDateTime"),
                    source="har",
                )
            )

        return exchanges


def _headers(items: list[dict[str, Any]]) -> dict[str, str]:
    return {
        str(item.get("name", "")).lower(): str(item.get("value", ""))
        for item in items
        if item.get("name")
    }


def _post_data(post_data: dict[str, Any] | None) -> Any:
    if not post_data:
        return None
    if "jsonObj" in post_data:
        return post_data["jsonObj"]
    return post_data.get("text")


def _content(content: dict[str, Any]) -> Any:
    if not content:
        return None
    return content.get("text")
