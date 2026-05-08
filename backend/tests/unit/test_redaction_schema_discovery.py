from app.analyzer.api_discovery import ApiDiscoveryAnalyzer
from app.analyzer.openapi_builder import OpenApiBuilder
from app.analyzer.schema_inference import infer_exchange_schemas
from app.parser.normalizer import normalize_url
from app.parser.redactor import TrafficRedactor


def test_redaction_replaces_secrets_and_keeps_findings() -> None:
    exchange = normalize_url(
        "POST",
        "https://example.com/api/posts",
        request_headers={
            "authorization": "Bearer real-token",
            "cookie": "sid=secret",
            "content-type": "application/json",
        },
        request_body={"title": "hello", "password": "super-secret", "phone": "13800138000"},
    )

    redacted = TrafficRedactor().redact_exchange(exchange)

    assert redacted.request_headers["authorization"] == "{{secrets.session.authorization}}"
    assert redacted.request_headers["cookie"] == "{{secrets.session.cookie}}"
    assert redacted.request_body["password"] == "{{secrets.session.password_not_saved}}"
    assert redacted.request_body["phone"] == "[PHONE]"
    assert redacted.redaction_report
    assert "real-token" not in redacted.model_dump_json()


def test_schema_inference_and_discovery_marks_write_and_risk() -> None:
    exchange = normalize_url(
        "POST",
        "https://example.com/api/posts/123?draft=1",
        request_headers={"content-type": "application/json", "authorization": "{{secrets.session.authorization}}"},
        request_body='{"title":"hello","content":"world"}',
        status=201,
    )
    exchange = infer_exchange_schemas(exchange)
    result = ApiDiscoveryAnalyzer().analyze([exchange])

    endpoint = result.endpoints[0]
    assert endpoint.path_template == "/api/posts/{id}"
    assert endpoint.query_schema == {"draft": "integer"}
    assert endpoint.request_body_schema is not None
    assert endpoint.operation_type == "write"
    assert endpoint.replay_risk == "high"


def test_openapi_builder_uses_redacted_metadata_without_empty_request_body() -> None:
    exchange = normalize_url(
        "GET",
        "https://example.com/api/posts?draft=1",
        request_headers={"cookie": "sid=secret-cookie"},
        status=200,
    )
    redacted = TrafficRedactor().redact_exchange(infer_exchange_schemas(exchange))
    result = ApiDiscoveryAnalyzer().analyze([redacted])

    spec = OpenApiBuilder().build(result)
    operation = spec["paths"]["/api/posts"]["get"]

    assert operation["x-dependencies"] == ["{{secrets.session.cookie}}"]
    assert operation["parameters"][0]["name"] == "draft"
    assert "requestBody" not in operation
    assert "secret-cookie" not in str(spec)
