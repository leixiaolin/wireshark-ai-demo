import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, Field


class SessionSecretCreate(BaseModel):
    name: str
    kind: str = "browser_state"
    allowed_domains: list[str] = Field(default_factory=list)
    data: dict[str, Any]


class SessionSecretInfo(BaseModel):
    id: str
    name: str
    kind: str
    allowed_domains: list[str] = Field(default_factory=list)
    created_at: str
    updated_at: str


class SessionSecretVault:
    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._fernet = Fernet(self._load_or_create_key())

    def create(self, request: SessionSecretCreate) -> SessionSecretInfo:
        secret_id = uuid4().hex
        now = _now()
        info = SessionSecretInfo(
            id=secret_id,
            name=request.name,
            kind=request.kind,
            allowed_domains=request.allowed_domains,
            created_at=now,
            updated_at=now,
        )
        self._write(info, request.data)
        return info

    def save_data(
        self,
        name: str,
        data: dict[str, Any],
        kind: str = "browser_state",
        allowed_domains: list[str] | None = None,
    ) -> SessionSecretInfo:
        return self.create(
            SessionSecretCreate(
                name=name,
                kind=kind,
                allowed_domains=allowed_domains or [],
                data=data,
            )
        )

    def list(self) -> list[SessionSecretInfo]:
        infos = []
        for meta_path in sorted(self.root_dir.glob("*.meta.json")):
            infos.append(SessionSecretInfo(**json.loads(meta_path.read_text(encoding="utf-8"))))
        return infos

    def get_info(self, secret_id: str) -> SessionSecretInfo:
        meta_path = self._meta_path(secret_id)
        if not meta_path.exists():
            raise KeyError(f"Unknown session secret: {secret_id}")
        return SessionSecretInfo(**json.loads(meta_path.read_text(encoding="utf-8")))

    def read_data(self, secret_id: str) -> dict[str, Any]:
        info = self.get_info(secret_id)
        blob_path = self._blob_path(info.id)
        try:
            plain = self._fernet.decrypt(blob_path.read_bytes())
        except InvalidToken as exc:
            raise RuntimeError(f"Failed to decrypt session secret: {secret_id}") from exc
        return json.loads(plain.decode("utf-8"))

    def delete(self, secret_id: str) -> None:
        self.get_info(secret_id)
        self._meta_path(secret_id).unlink(missing_ok=True)
        self._blob_path(secret_id).unlink(missing_ok=True)

    def _write(self, info: SessionSecretInfo, data: dict[str, Any]) -> None:
        self._meta_path(info.id).write_text(info.model_dump_json(indent=2), encoding="utf-8")
        plain = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._blob_path(info.id).write_bytes(self._fernet.encrypt(plain))

    def _load_or_create_key(self) -> bytes:
        key_path = self.root_dir / ".vault.key"
        if key_path.exists():
            return key_path.read_bytes()
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        return key

    def _meta_path(self, secret_id: str) -> Path:
        return self.root_dir / f"{secret_id}.meta.json"

    def _blob_path(self, secret_id: str) -> Path:
        return self.root_dir / f"{secret_id}.secret"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
