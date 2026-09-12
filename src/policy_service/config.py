from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="POL_", extra="ignore")

    database_url: str = "postgresql+psycopg://policy:policy@localhost:5437/policy"
    bootstrap_token: str = ""

    # Trusted IAM context: policy-service принимает только короткоживущий
    # audience-bound access token iam-service.
    iam_issuer: str = "http://localhost:8010"
    iam_audience: str = "policy-service"
    iam_public_key: str = ""
    iam_public_key_file: str = ""
    iam_jwks_url: str = ""

    # Engine (OpenFGA) — deployment profile, наружу не публикуется.
    fga_url: str = "http://localhost:8080"
    fga_preshared_key: str = ""
    fga_timeout_seconds: float = 3.0
    fga_store_prefix: str = "taimen"

    # Каталоги действий, загружаемые при старте (пути к yaml/json через запятую).
    catalog_files: str = ""

    # Источники проекции отношений (pull-воркер).
    control_plane_url: str = ""
    control_plane_token: str = ""
    iam_url: str = ""
    iam_events_bootstrap_token: str = ""
    projection_poll_seconds: float = 2.0
    projection_batch_size: int = 200

    create_schema_on_startup: bool = False

    def resolved_iam_public_key(self) -> str:
        if self.iam_public_key:
            return self.iam_public_key
        if self.iam_public_key_file:
            return Path(self.iam_public_key_file).read_text()
        return ""

    def catalog_paths(self) -> list[Path]:
        return [Path(p.strip()) for p in self.catalog_files.split(",") if p.strip()]
