from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from policy_service.app import create_app
from policy_service.config import Settings

BOOTSTRAP_TOKEN = "test-bootstrap-token"
BOOTSTRAP_HEADERS = {"X-Policy-Bootstrap-Token": BOOTSTRAP_TOKEN}
IAM_ISSUER = "https://iam.example"
IAM_AUDIENCE = "policy-service"
FGA_URL = os.environ.get("POL_TEST_FGA_URL", "http://127.0.0.1:18090")
FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).resolve().parents[2]


def fga_available() -> bool:
    try:
        return httpx.get(f"{FGA_URL}/healthz", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


requires_fga = pytest.mark.skipif(
    not fga_available(), reason=f"нет живого OpenFGA по {FGA_URL} (POL_TEST_FGA_URL)"
)


def _keypair() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private_pem, public_pem


class Environment:
    def __init__(self, client: TestClient, iam_private_key: str) -> None:
        self.client = client
        self.iam_private_key = iam_private_key

    def iam_token(
        self,
        tenant_id: uuid.UUID | str,
        *,
        subject_id: uuid.UUID | str | None = None,
        scopes: list[str] | None = None,
        principal_type: str = "service_account",
        audience: str = IAM_AUDIENCE,
        expires_in: int = 300,
    ) -> str:
        now = datetime.now(UTC)
        return jwt.encode(
            {
                "iss": IAM_ISSUER,
                "sub": str(subject_id or uuid.uuid4()),
                "tenant_id": str(tenant_id),
                "aud": audience,
                "scope": scopes or [],
                "principal_type": principal_type,
                "credential_id": str(uuid.uuid4()),
                "iat": now,
                "nbf": now,
                "exp": now + timedelta(seconds=expires_in),
                "jti": str(uuid.uuid4()),
            },
            self.iam_private_key,
            algorithm="RS256",
        )

    def auth(self, tenant_id: uuid.UUID | str, **kwargs: object) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.iam_token(tenant_id, **kwargs)}"}  # type: ignore[arg-type]


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Environment]:
    private_pem, public_pem = _keypair()
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'policy.db'}",
        bootstrap_token=BOOTSTRAP_TOKEN,
        iam_issuer=IAM_ISSUER,
        iam_audience=IAM_AUDIENCE,
        iam_public_key=public_pem,
        fga_url=FGA_URL,
        fga_store_prefix=f"test-{uuid.uuid4().hex[:6]}",
        create_schema_on_startup=True,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        yield Environment(client, private_pem)


def catalog_paths() -> list[Path]:
    """Закреплённые каталоги-фикстуры: на них проверяется семантика модели и проекции.

    Сервис заморожен (TAI-ADR-0039), а каталоги соседей развиваются дальше: семантические
    тесты на живых каталогах ломались бы от каждого нового действия ядра.
    """
    return sorted(FIXTURES.glob("*.yaml"))


def live_catalog_paths() -> list[Path]:
    """Реальные каталоги из соседних сабмодулей, если они есть, иначе фикстуры."""
    real = [ROOT / "control-plane/authz/catalog.yaml", ROOT / "memory-service/authz/catalog.yaml"]
    if all(p.exists() for p in real):
        return real
    return catalog_paths()
