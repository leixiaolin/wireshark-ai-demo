from app.secrets.vault import SessionSecretCreate, SessionSecretVault


def test_vault_encrypts_data_and_lists_metadata(tmp_path) -> None:
    vault = SessionSecretVault(tmp_path)
    info = vault.create(
        SessionSecretCreate(
            name="csdn",
            kind="playwright_storage_state",
            allowed_domains=["editor.csdn.net"],
            data={"storage_state": {"cookies": [{"name": "sid", "value": "secret-cookie"}]}},
        )
    )

    assert vault.list()[0].name == "csdn"
    assert vault.read_data(info.id)["storage_state"]["cookies"][0]["value"] == "secret-cookie"
    assert "secret-cookie" not in (tmp_path / f"{info.id}.secret").read_text(encoding="utf-8")

    vault.delete(info.id)
    assert vault.list() == []
