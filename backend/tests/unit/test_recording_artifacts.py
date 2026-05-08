from app.parser.normalizer import normalize_url
from app.recording.manager import RecordingManager, RecordingRecord, RecordingStatus
from app.secrets.vault import SessionSecretVault


def test_recording_artifacts_are_redacted_and_reviewable(tmp_path) -> None:
    vault = SessionSecretVault(tmp_path / "vault")
    manager = RecordingManager(tmp_path / "recordings", vault)
    status = RecordingStatus(
        id="rec1",
        name="demo",
        status="stopped",
        url="https://example.com/editor",
        allowed_domains=["example.com"],
        started_at="2026-05-08T00:00:00+00:00",
        stopped_at="2026-05-08T00:01:00+00:00",
        secret_ref="{{secrets.session.sid}}",
        exchange_count=1,
    )
    redacted = normalize_url(
        "POST",
        "https://example.com/api/posts",
        request_headers={"content-type": "application/json", "authorization": "{{secrets.session.authorization}}"},
        request_body={"title": "hello"},
        status=201,
        resource_type="fetch",
    )
    redacted.secret_refs = {"request.headers.authorization": "{{secrets.session.authorization}}"}
    manager._write_record(RecordingRecord(status=status, redacted_exchanges=[redacted]))

    apis = manager.apis("rec1")
    http_workflow = manager.http_workflow("rec1")
    browser_workflow = manager.browser_workflow("rec1")
    analysis = manager.analyze("rec1")

    assert apis["endpoints"][0]["operation_type"] == "write"
    assert http_workflow["dry_run"] is True
    assert http_workflow["steps"][0]["requires_review"] is True
    assert browser_workflow["auth_secret_ref"] == "{{secrets.session.sid}}"
    assert analysis["input_policy"] == "redacted_summary_only"
    assert "Bearer" not in str(analysis)
