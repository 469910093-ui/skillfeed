"""服务端配置（环境变量）。"""

from __future__ import annotations

import os
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def data_home() -> Path:
    env = _env("SKILLFEED_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / ".skill-feed").resolve()


class Settings:
    def __init__(self) -> None:
        self.session_secret = _env("SKILLFEED_SESSION_SECRET") or "dev-only-change-me"
        self.public_url = _env("SKILLFEED_PUBLIC_URL", "http://127.0.0.1:8787").rstrip("/")
        self.github_client_id = _env("SKILLFEED_GITHUB_CLIENT_ID")
        self.github_client_secret = _env("SKILLFEED_GITHUB_CLIENT_SECRET")
        self.official_feed_url = _env(
            "SKILLFEED_OFFICIAL_FEED_URL",
            "https://469910093-ui.github.io/skillfeed/feed.json",
        )
        db = _env("SKILLFEED_DB")
        self.db_path = Path(db).expanduser() if db else (data_home() / "server.db")
        origins = _env(
            "SKILLFEED_CORS_ORIGINS",
            "https://469910093-ui.github.io,http://127.0.0.1:8473,http://127.0.0.1:8787",
        )
        self.cors_origins = [o.strip() for o in origins.split(",") if o.strip()]
        self.cookie_name = "skillfeed_session"
        self.cookie_max_age = 60 * 60 * 24 * 30  # 30d
        self.dev_auth = _env("SKILLFEED_DEV_AUTH", "0") in ("1", "true", "yes")

    @property
    def oauth_configured(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret)


def get_settings() -> Settings:
    return Settings()
