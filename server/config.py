"""服务端配置（环境变量）。"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

# 曾经作为缺省值写死在本文件里、因此已经公开的会话密钥
PUBLISHED_SECRETS = frozenset({
    "dev-only-change-me",
    "change-me",
    "secret",
    # .env.example 一度直接发这个字面量，照抄的人等于没有密钥
    "change-me-to-a-long-random-string",
})


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def data_home() -> Path:
    env = _env("SKILLFEED_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / ".skill-feed").resolve()


class Settings:
    def __init__(self) -> None:
        # SKILLFEED_DEV 是所有降级路径的总开关。生产环境不会设它，
        # 所以「漏配某个环境变量」只会让站点更严，不会让它变得可以随便登进来。
        self.dev_mode = _env("SKILLFEED_DEV", "0") in ("1", "true", "yes")

        secret = _env("SKILLFEED_SESSION_SECRET")
        self.session_secret_source = "env"
        if not secret:
            if self.dev_mode:
                # 随机密钥：进程重启后所有会话失效，这是刻意的，不要为了「方便」
                # 回退到写死的常量——写死的常量在公开仓库里，等于没有会话签名
                secret = secrets.token_urlsafe(32)
                self.session_secret_source = "ephemeral"
            else:
                self.session_secret_source = "missing"
        self.session_secret = secret
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
        # 无凭据登录要两把钥匙同时在：单独设 SKILLFEED_DEV_AUTH=1 不生效
        self.dev_auth = (
            _env("SKILLFEED_DEV_AUTH", "0") in ("1", "true", "yes") and self.dev_mode
        )
        # 受信反向代理配置。两个都要设才会读 X-Forwarded-For。
        # ⚠️ 默认值和生产值不同，这是最容易踩的坑：
        #   - 本地/直连：全部留空（默认）。此时完全不读 XFF，按 socket 地址分桶
        #   - 阿里云轻量 + 同机 Nginx：HOPS=1，IPS=127.0.0.1
        #   - CDN → Nginx 两层：HOPS=2，IPS=<Nginx 出口地址>
        # 只配 HOPS 不配 IPS 无效——没有可信对端就无法判断请求是否真的走过代理，
        # 这时候读 XFF 等于让任何人伪造一个头就换限流桶。
        try:
            self.trusted_proxy_hops = max(0, int(_env("SKILLFEED_TRUSTED_PROXY_HOPS", "0")))
        except ValueError:
            self.trusted_proxy_hops = 0
        self.trusted_proxy_ips = frozenset(
            p.strip() for p in _env("SKILLFEED_TRUSTED_PROXY_IPS").split(",") if p.strip()
        )
        # 运维只读令牌：给监控/CI 拉埋点健康和站内热度导出用。
        # 不设就只能靠登录态访问那两个端点——不会退化成公开可读
        self.metrics_token = _env("SKILLFEED_METRICS_TOKEN")
        self.config = self._load_config()

    def _load_config(self) -> dict[str, Any]:
        """仓库默认值打底，用户目录的 config.json 覆盖。两个都缺就走代码侧默认。"""
        merged = _read_json(REPO_ROOT / "config_defaults.json")
        merged.update(_read_json(data_home() / "config.json"))
        return merged

    @property
    def ranking_config(self) -> dict[str, Any]:
        return self.config

    @property
    def oauth_configured(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret)

    @property
    def dev_login_allowed(self) -> bool:
        """无凭据登录的启用条件，任缺一条即关闭。

        https 站点一律禁用：真实部署会走 https，这条让生产环境即使误设了
        两个 DEV 变量也进不去无凭据登录。
        """
        return (
            self.dev_mode
            and self.dev_auth
            and not self.public_url.startswith("https://")
        )

    def assert_bootable(self) -> None:
        """启动前自检。fail-closed：宁可起不来，也不要带着可伪造的会话密钥上线。"""
        # 这些值曾经或可能出现在公开仓库里，等于没有密钥
        if self.session_secret in PUBLISHED_SECRETS and not self.dev_mode:
            raise RuntimeError(
                f"SKILLFEED_SESSION_SECRET 不能用 {self.session_secret!r}："
                "这个值出现在公开仓库里，任何人都能拿它自签 cookie 冒充任意用户。"
            )
        if not self.session_secret:
            raise RuntimeError(
                "未设置 SKILLFEED_SESSION_SECRET。会话 cookie 用它做 HMAC 签名，"
                "缺了就等于任何人都能自签一个 cookie 冒充任意用户。\n"
                "  生产：export SKILLFEED_SESSION_SECRET=$(python -c \"import secrets;print(secrets.token_urlsafe(32))\")\n"
                "  本地：export SKILLFEED_DEV=1（自动生成临时密钥，重启后会话全失效）"
            )

    def startup_notes(self) -> list[str]:
        notes: list[str] = []
        if self.session_secret_source == "ephemeral":
            notes.append(
                "[warn] 使用随机生成的临时会话密钥（SKILLFEED_DEV=1）。"
                "进程重启后所有登录态失效，仅供本地开发。"
            )
        if self.dev_login_allowed:
            notes.append(
                "[warn] 无凭据登录 /auth/dev-login 已启用（SKILLFEED_DEV=1 + "
                "SKILLFEED_DEV_AUTH=1 + 非 https）。任何人访问该地址即可获得会话，"
                "不要暴露到公网。"
            )
        if not (self.trusted_proxy_hops and self.trusted_proxy_ips):
            notes.append(
                "[info] 不信任 X-Forwarded-For，限流按 socket 对端地址分桶。"
                "若部署在 Nginx 后面，请同时设 SKILLFEED_TRUSTED_PROXY_HOPS=1 和 "
                "SKILLFEED_TRUSTED_PROXY_IPS=127.0.0.1，否则全站共用一个限流桶。"
            )
        return notes


def get_settings() -> Settings:
    return Settings()
