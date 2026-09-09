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


def _env_any(*names: str, default: str = "") -> str:
    """按顺序取第一个非空的变量名。

    任务清单里给的名字是 `WECHAT_APP_ID` 这种裸名，仓库其余配置一律 `SKILLFEED_`
    前缀。两种都读、前缀版优先：既不违背清单，也不在同一个进程里搞出两套命名。
    """
    for n in names:
        v = _env(n)
        if v:
            return v
    return default


def _flag(name: str, default: str = "0") -> bool:
    return _env(name, default).lower() in ("1", "true", "yes", "on")


def _int_env(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


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
        # GitHub 登录在 V1 降级为可选「绑定」：代码保留，登录页默认不给入口。
        # 设 1 才把按钮显示出来（比如给自己用的运维通道）
        self.github_login_visible = _flag("SKILLFEED_GITHUB_LOGIN_VISIBLE", "0")

        # —— 主站强制登录 ——
        # 默认 1 而不是 0：V1 的定案就是强制登录，而「漏配一个环境变量」的后果
        # 应该是站点更严，不是门禁静默消失。本地要开着门调试就显式设 0。
        self.require_login = (
            _env("SKILLFEED_REQUIRE_LOGIN", "1").lower() not in ("0", "false", "no", "off")
        )

        # —— 微信服务号网页授权 ——
        self.wechat_app_id = _env_any("SKILLFEED_WECHAT_APP_ID", "WECHAT_APP_ID")
        # ⚠️ AppSecret 只在服务端 → 微信 API 的这一跳里出现。
        # 不进任何响应体、不进日志、不进 __repr__（见本类 __repr__）
        self.wechat_app_secret = _env_any("SKILLFEED_WECHAT_APP_SECRET", "WECHAT_APP_SECRET")
        # snsapi_userinfo 要用户点一次授权、能拿昵称头像；snsapi_base 静默只给 openid。
        # 默认要昵称头像，因为「我的账户」要显示人。
        self.wechat_scope = _env("SKILLFEED_WECHAT_SCOPE", "snsapi_userinfo")
        self.oauth_state_ttl_s = _int_env("SKILLFEED_OAUTH_STATE_TTL_S", 600)

        # —— 短信验证码兜底 ——
        # provider: "" = 未配置（/auth/sms/send 直接 503）；"aliyun" = 阿里云短信；
        # "console" = 只打到服务端日志，仅 SKILLFEED_DEV=1 时可用
        self.sms_provider = _env_any("SKILLFEED_SMS_PROVIDER", "SMS_PROVIDER").lower()
        self.sms_sign_name = _env_any("SKILLFEED_SMS_SIGN_NAME", "SMS_SIGN_NAME")
        self.sms_template_code = _env_any("SKILLFEED_SMS_TEMPLATE_CODE", "SMS_TEMPLATE_CODE")
        # ⚠️ 同 AppSecret：只往上游走，不往下游走
        self.sms_access_key_id = _env_any("SKILLFEED_SMS_ACCESS_KEY_ID", "SMS_ACCESS_KEY_ID")
        self.sms_access_key_secret = _env_any(
            "SKILLFEED_SMS_ACCESS_KEY_SECRET", "SMS_ACCESS_KEY_SECRET",
        )
        self.sms_region = _env_any(
            "SKILLFEED_SMS_REGION", "SMS_REGION", default="cn-hangzhou",
        )
        self.sms_code_ttl_s = _int_env("SKILLFEED_SMS_CODE_TTL_S", 300)
        self.sms_max_attempts = _int_env("SKILLFEED_SMS_MAX_ATTEMPTS", 5)
        self.sms_resend_cooldown_s = _int_env("SKILLFEED_SMS_RESEND_COOLDOWN_S", 60)
        self.sms_window_s = _int_env("SKILLFEED_SMS_WINDOW_S", 3600)
        self.sms_max_per_phone = _int_env("SKILLFEED_SMS_MAX_PER_PHONE", 5)
        self.sms_max_per_ip = _int_env("SKILLFEED_SMS_MAX_PER_IP", 20)
        self.sms_max_verify_per_ip = _int_env("SKILLFEED_SMS_MAX_VERIFY_PER_IP", 30)

        # 官方发现源。**默认不再指向 github.io**：主站是国内域名，浏览器从国内
        # 拉 github.io 时快时慢时不通，而 Feed 是首屏内容。默认走服务器本地产物
        # （`python skillfeed.py publish-site --out site` 的输出），
        # 同源、无出网、无跨境延迟。
        self.official_feed_url = _env("SKILLFEED_OFFICIAL_FEED_URL")
        site = _env("SKILLFEED_SITE_DIR")
        self.site_dir = Path(site).expanduser() if site else (data_home() / "site")
        feed_file = _env("SKILLFEED_OFFICIAL_FEED_FILE")
        self.official_feed_file = (
            Path(feed_file).expanduser() if feed_file else (self.site_dir / "feed.json")
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

    def __repr__(self) -> str:  # pragma: no cover - 仅影响日志/调试输出
        """脱敏的 repr。

        Settings 里现在装着 AppSecret 和短信 AK。默认 repr 虽然不打属性，
        但只要有人写了 `logging.info("settings=%s", vars(settings))`
        或者某个异常处理把对象整个塞进 traceback 附注，凭据就进日志了。
        显式定义一个只打非敏感项的 repr，把这条路堵死。
        """
        return (
            f"Settings(public_url={self.public_url!r}, require_login={self.require_login}, "
            f"wechat_configured={self.wechat_configured}, sms_configured={self.sms_configured}, "
            f"dev_mode={self.dev_mode})"
        )

    @property
    def oauth_configured(self) -> bool:
        return bool(self.github_client_id and self.github_client_secret)

    @property
    def wechat_configured(self) -> bool:
        return bool(self.wechat_app_id and self.wechat_app_secret)

    @property
    def sms_configured(self) -> bool:
        """短信是否真能发出去。

        console provider 只在 dev 下算「配置好了」：它把验证码打到服务端日志，
        谁能看日志谁就能登任意手机号，生产环境必须当成未配置。
        """
        if self.sms_provider == "console":
            return self.dev_mode
        if self.sms_provider == "aliyun":
            return bool(
                self.sms_access_key_id
                and self.sms_access_key_secret
                and self.sms_sign_name
                and self.sms_template_code
            )
        return False

    @property
    def any_login_available(self) -> bool:
        return bool(
            self.wechat_configured
            or self.sms_configured
            or self.oauth_configured
            or self.dev_login_allowed
        )

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
        if self.require_login and not self.any_login_available:
            # 刻意只是 warn 不是 raise：第 2 期的代码要能在拿到服务号凭据之前
            # 先合进来。但必须响一声，否则「站点起来了但谁也登不进去」
            # 只能靠用户报障发现。
            notes.append(
                "[warn] SKILLFEED_REQUIRE_LOGIN=1 但没有任何可用登录方式："
                "微信（SKILLFEED_WECHAT_APP_ID/SECRET）、短信（SKILLFEED_SMS_*）、"
                "GitHub OAuth 都未配置。现在全站会 302 到 /login 且登不进去。"
            )
        if not self.require_login:
            notes.append(
                "[warn] 登录门禁已关闭（SKILLFEED_REQUIRE_LOGIN=0）。"
                "Feed 与各 API 对未登录者开放，仅供本地开发。"
            )
        if self.sms_provider == "console" and self.dev_mode:
            notes.append(
                "[warn] 短信走 console provider：验证码只打印到服务端日志，"
                "任何能看日志的人都能登任意手机号。不要用于公网。"
            )
        if self.require_login and not self.public_url.startswith("https://"):
            notes.append(
                "[info] SKILLFEED_PUBLIC_URL 不是 https，会话 cookie 不会带 Secure。"
                "公网部署务必配 https 并把该变量改成 https 地址。"
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
