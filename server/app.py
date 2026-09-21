"""skill-feed 云端 API：GitHub 登录 + UGC 发布 + 混排 Feed。"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from html import escape as html_escape
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

from fastapi import Body, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import geo
import ranking
from server import auth, backup, db, entitlement, metrics, notify, pay, ranking_service, sms, ugc
from server.config import Settings, get_settings
from server.ratelimit import EventLimiter, GeoLimiter, SmsLimiter

ROOT = Path(__file__).resolve().parent
TEMPLATES = ROOT / "templates"

MAX_EVENTS_PER_REQUEST = 200

# 登录成功后回跳的落点。只存已消毒的站内路径，见 _safe_next
LOGIN_NEXT_COOKIE = "skillfeed_login_next"


class PostCreate(BaseModel):
    title: str = ""
    github_url: str = ""
    description: str = ""
    body_md: str = ""  # 旧客户端字段；服务端丢弃，不落库


class ModerateBody(BaseModel):
    action: str = Field(pattern="^(approve|reject|hide|feature|ban)$")
    note: str = ""
    ban_author: bool = False


class ReactBody(BaseModel):
    kind: str = Field(pattern="^(like|save|bad)$")
    on: bool = True


class EventsBody(BaseModel):
    device_id: str = ""
    session_id: str = ""
    events: list[dict] = Field(default_factory=list)


class ClaimBody(BaseModel):
    device_id: str = ""
    device_token: str = ""


class SmsSendBody(BaseModel):
    phone: str = ""


class SmsVerifyBody(BaseModel):
    phone: str = ""
    code: str = ""
    next: str = ""


class ActivateBody(BaseModel):
    code: str = ""


class SiteSettingsBody(BaseModel):
    slogan: str = ""
    search_placeholder: str = ""
    logo_url: str = ""
    review_webhook: str = ""


class PayCreateBody(BaseModel):
    sku: str = pay.SKU_YEAR


class PayDevNotifyBody(BaseModel):
    out_trade_no: str = ""
    transaction_id: str = ""


# —— 登录门禁的豁免表 ——
#
# 这是一份**白名单**，中间件的逻辑是「不在表里就要登录」。
# 反过来写（黑名单：列出需要登录的路径）的话，以后新增一个路由忘了登记，
# 它就默认是公开的 —— 而「忘了」是一定会发生的。默认拒绝意味着忘记的代价是
# 「这个接口 302 到登录页」，能立刻被发现；而不是「这个接口悄悄对全网开放」。
#
# 每一条豁免都要有理由：
GATE_PUBLIC_EXACT = frozenset({
    "/health",      # 外部 uptime 探针，不可能带登录态
    "/login",       # 登录页自己。它要是被拦，就是无限重定向
    "/favicon.ico",  # 浏览器自动请求；现在真有文件，不再只是挡 302
    "/favicon.png",
    "/apple-touch-icon.png",
    "/og.png",
    # 发现流全量免费：hydrateLiveFeed 用它把已过审 UGC 混进静态首页。
    # 只出 published/approved，pending 不会从这里漏出去。
    "/api/feed",
    "/api/site-config",
    # 游客进站路径也要记：首页是 Nginx 静态页，多数人还没登录。
    # 已有 IP/设备限流；不记 IP / UA。运营读走 /op「路径」，不公开。
    "/api/events",
    # 微信支付回调没有会话 Cookie。开通只信验签后的 out_trade_no，
    # 未配置 / 验签未接时这个端点只会 503，不会发权益。
    "/api/pay/wechat/notify",
    # Agent Surface：给模型读的公开文件与查询口。不含打分、不含运营面。
    "/llms.txt",
    "/llms-full.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/about.md",
    "/faq.md",
    "/compare.md",
    "/catalog.json",
    "/api/geo/skills",
    "/api/geo/openapi.json",
})
GATE_PUBLIC_PREFIXES = (
    # 所有登录相关端点：发起跳转、各家回调、短信收发、退出、/auth/me。
    # 微信回调必须公开 —— 那一跳的目的正是「还没有会话，去建一个」。
    "/auth/",
    # 登录页要用到的静态资源；这个目录里不放任何用户数据
    "/static/",
    # 卡片短链 /p/zhangleme，聊天软件不会在冒号处截断
    "/p/",
    # 公开目录检索与单条详情。完整 /docs 仍在门禁后。
    "/api/geo/",
)


def _is_gate_public(path: str) -> bool:
    return path in GATE_PUBLIC_EXACT or path.startswith(GATE_PUBLIC_PREFIXES)


def _safe_next(raw: str) -> str:
    """把 `?next=` 收敛成本站内部路径，挡开放重定向。

    `next` 会被写进登录成功后的 302 Location。不校验的话
    `/login?next=https://evil.example` 就是一个挂在本站域名下的钓鱼跳板。

    只接受以单个 `/` 开头的路径：`//evil.com` 在浏览器里等价于协议相对 URL，
    反斜杠也被部分浏览器当成路径分隔符，两者都要排除。

    控制字符也要排除：`next` 会进 `Location` 响应头，夹一个 CRLF 就是响应头注入。
    引号和尖括号同样排除 —— 这个值还会被写进登录页的 HTML（那里另有转义，
    但两道都做，任一处被改坏另一处还在）。
    """
    nxt = (raw or "").strip()
    if not nxt.startswith("/") or nxt.startswith("//") or "\\" in nxt:
        return "/"
    if any(ch in nxt for ch in "\r\n\t\"'<>") or any(ord(ch) < 0x20 for ch in nxt):
        return "/"
    if nxt.startswith("/login"):
        # 登录成功又跳回登录页，用户会以为没登上
        return "/"
    return nxt[:512]


def _client_ip(
    request: Request,
    trusted_hops: int = 0,
    trusted_ips: Optional[frozenset[str]] = None,
) -> str:
    """限流分桶用的客户端标识。

    X-Forwarded-For 的**首段是客户端自己写的**，无条件信任它等于把限流关掉：
    伪造一行头就能换一个桶，而限流存在的理由正是防止有人刷 CTR 顶自己上首页。

    但在反向代理后面又必须读它，否则所有请求都来自代理 IP、全站共用一个桶。
    所以要两个条件同时成立才读这个头：

    1. **socket 对端必须是受信代理**。只看链长度不够——「客户端直连并伪造一段」
       和「Nginx 追加了一段」都是长度 1，分不开。对端地址是伪造不了的，
       用它判断请求到底有没有走过代理链。
    2. **从右往左数第 N 跳**。Nginx 的 $proxy_add_x_forwarded_for 把它实际看到的
       地址追加在最右边，右侧 N 段是各层代理写的，左侧才是客户端可控的部分。

    任一条件不满足就退回 socket 地址（更严，不会误放行）。
    """
    peer = request.client.host if request.client else "unknown"
    if trusted_hops <= 0 or not trusted_ips or peer not in trusted_ips:
        return peer
    chain = [p.strip() for p in (request.headers.get("x-forwarded-for") or "").split(",")]
    chain = [p for p in chain if p]
    if len(chain) < trusted_hops:
        return peer
    return chain[-trusted_hops]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _age_s(ts: Optional[str]) -> Optional[float]:
    """距 `ts` 过了多少秒。未来时间返回负数，解析不了返回 None。

    不用 metrics.staleness：那个函数把结果 clamp 到 >=0，用它判断
    「expires_at 是否已过」会把「还没过期」误判成「刚好过期」，
    等于验证码永不过期。
    """
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).total_seconds()


def _device_id(request: Request, query_value: str = "") -> str:
    """优先读请求头。

    device_id 走 query param 会被写进 Nginx access log 和 Referer 头，
    等于把「劫持匿名画像所需的那半个凭据」到处散播。保留 query 只为兼容。
    """
    return ((request.headers.get("x-device-id") or "").strip() or (query_value or "").strip())[:64]


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # 顺带堵住 device_id 经 Referer 外泄
    "Referrer-Policy": "no-referrer",
}

# script-src 严格到 nonce：注入进来的 <script> 一律不执行，这是本策略的主要目的。
# style-src 保留 unsafe-inline 是有意的取舍——模板里有 style="display:none" 这类
# 内联属性，nonce 覆盖不到它们（CSP 里 nonce 只作用于 <style> 元素，不作用于
# style 属性），强上 nonce 会直接白屏。样式注入无法执行脚本，风险等级远低于 script。
CSP_HTML = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-{nonce}'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: https:; "
    "connect-src 'self'; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)
# JSON 响应不需要任何子资源，能锁死就锁死
CSP_API = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"

# 由 feed_dashboard.py 生成、publish-site 落盘的那份主站 HTML。
# 它把脚本整段内联在 <script> 里，nonce 注入不到（模板生成器在另一支演进中，
# 本次改动不碰它），所以这条策略必须放开 script-src 的 'unsafe-inline'，
# 否则页面直接白屏。
#
# 取舍说明：这份产物是**我们自己的构建输出**，不是用户提交的内容，内联脚本
# 就是我们的代码。它此前一直挂在 GitHub Pages 上、**完全没有 CSP**，
# 所以这条策略相对现状是净收紧（object-src/base-uri/frame-ancestors 全锁）。
# 后续 feed_dashboard.py 改造完成后应该换成 nonce，见 README 的待办。
CSP_SITE = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "img-src 'self' data: https:; "
    "connect-src 'self' https:; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


def _apply_feed_quota(
    request: Request,
    settings: Settings,
    items: list[dict[str, Any]],
    *,
    claim: bool = True,
) -> tuple[list[dict[str, Any]], Optional[dict[str, Any]]]:
    """发现流全量免费：登录用户拿完整 items，quota.unlimited=True。"""
    uid = auth.session_user_id(request, settings)
    if uid is None:
        return list(items), None
    with db.db_session(settings.db_path) as conn:
        user = db.get_user(conn, uid)
        return entitlement.apply_daily_quota(
            conn, user, items,
            limit=settings.free_daily_feed_items,
            claim=claim,
        )


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or get_settings()
    settings.assert_bootable()
    db.init_db(settings.db_path)

    app = FastAPI(
        title="skill-feed API",
        version="0.2.0",
        description="GitHub 登录 · UGC 发布 skill · 混排 Feed（不代装）",
    )
    app.state.settings = settings
    app.state.ranking_config = ranking.resolve_config(settings.ranking_config)
    app.state.event_limiter = EventLimiter(app.state.ranking_config)
    app.state.order_cache = ranking_service.SessionOrderCache(
        ttl_s=float(app.state.ranking_config["session"]["order_ttl_s"]),
    )
    app.state.ingest_metrics = metrics.IngestMetrics()
    app.state.sms_limiter = SmsLimiter(
        window_s=settings.sms_window_s,
        max_per_phone=settings.sms_max_per_phone,
        max_per_ip=settings.sms_max_per_ip,
        max_verify_per_ip=settings.sms_max_verify_per_ip,
    )
    app.state.geo_limiter = GeoLimiter()

    def require_ops(request: Request) -> None:
        """运维端点的门禁：登录态或运维令牌，二者取其一。

        不做成公开只读：这些端点会暴露按原因分类的丢弃计数，其中包含限流命中数。
        限流故意静默丢弃就是为了不让刷量的人二分试探阈值，公开一个会随他的
        请求增长的计数器等于把那道设计原样送回去。
        """
        token = (request.headers.get("x-metrics-token") or "").strip()
        # 比字节不比字符串：compare_digest 对含非 ASCII 的 str 会直接抛 TypeError，
        # 那样一个中文令牌能让运维端点变成 500 而不是 401
        if settings.metrics_token and hmac.compare_digest(
            token.encode("utf-8"), settings.metrics_token.encode("utf-8"),
        ):
            return
        auth.require_user_id(request, settings)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins or ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 注意添加顺序：Starlette 里**后加的在外层**。login_gate 加在
    # security_headers 之前，于是 security_headers 包在外面，
    # 门禁吐出的那条 302 也会带上安全响应头。
    @app.middleware("http")
    async def login_gate(request: Request, call_next):
        """主站强制登录。未登录 → 302 /login。

        默认拒绝：只有 `_is_gate_public` 认的路径能免登录，其余（包括以后新增的
        路由、/docs、/openapi.json）一律要会话。

        对 `/api/*` 也发 302 而不是 401 —— 这是产品侧定的口径（未登录一律回登录页）。
        前端用 fetch 时靠 `response.redirected` / `response.url` 判断，
        或者读这里带的 `X-Login-Required` 头（redirect: "manual" 时可见）。
        """
        if settings.require_login and not _is_gate_public(request.url.path):
            if auth.session_user_id(request, settings) is None:
                target = request.url.path
                if request.url.query:
                    target = f"{target}?{request.url.query}"
                dest = "/login"
                if target not in ("/", ""):
                    dest = f"/login?next={quote(target, safe='')}"
                resp = RedirectResponse(dest, status_code=302)
                resp.headers["X-Login-Required"] = "1"
                return resp
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        # HTML 页面的 CSP 由各自的响应带上（要塞 nonce），其余一律用最严的那条
        response.headers.setdefault("Content-Security-Policy", CSP_API)
        return response

    def html_response(html: str, nonce: str) -> HTMLResponse:
        resp = HTMLResponse(html)
        resp.headers["Content-Security-Policy"] = CSP_HTML.format(nonce=nonce)
        return resp

    static_dir = ROOT / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/health")
    def health() -> dict[str, Any]:
        # 埋点摄入的两个粗粒度量放公开健康检查里，外部 uptime 探针不用凭据
        # 就能盯住「零新增」。这里刻意不含限流命中数和拒绝原因，
        # 那些在 /api/events/health 后面（见 require_ops 的说明）
        with db.db_session(settings.db_path) as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n, MAX(ts) AS last_ts FROM events",
            ).fetchone()
        age = metrics.staleness(row["last_ts"])
        stale_after = float(app.state.ranking_config["ingest"]["stale_after_s"])
        return {
            "ok": True,
            "oauth": settings.oauth_configured,
            "wechat": settings.wechat_configured,
            # 只报「通道配好没有」，不报签名/模板/AK 任何取值
            "sms": settings.sms_configured,
            "review_webhook": bool(notify.resolve_review_webhook(settings)),
            "require_login": settings.require_login,
            "dev_auth": settings.dev_auth,
            "official_feed": bool(
                settings.official_feed_url or settings.official_feed_file.exists()
            ),
            "events_total": int(row["n"] or 0),
            "last_event_age_s": round(age, 1) if age is not None else None,
            "ingest_stale": bool(age is not None and age > stale_after),
        }

    def _geo_items() -> list[dict[str, Any]]:
        official: list[dict] = []
        if settings.official_feed_file.exists():
            official = ugc.load_official_items_from_file(settings.official_feed_file)
        ugc_items: list[dict] = []
        with db.db_session(settings.db_path) as conn:
            posts = db.list_published_posts(conn, limit=200, offset=0)
            ugc_items = [ugc.post_to_feed_item(p) for p in posts]
        return geo.sanitize_items(list(ugc_items) + list(official))

    def _geo_markdown(name: str, body: str, *, ext: str = "md") -> PlainTextResponse:
        media = "text/markdown; charset=utf-8" if ext == "md" else "text/plain; charset=utf-8"
        if name == "xml":
            media = "application/xml; charset=utf-8"
        return PlainTextResponse(body, media_type=media)

    @app.get("/llms.txt")
    def llms_txt() -> PlainTextResponse:
        items = _geo_items()
        return _geo_markdown("txt", geo.render_llms_txt(full=True, item_count=len(items)), ext="txt")

    @app.get("/llms-full.txt")
    def llms_full_txt() -> PlainTextResponse:
        return _geo_markdown("txt", geo.render_llms_full_txt(_geo_items(), full=True), ext="txt")

    @app.get("/robots.txt")
    def robots_txt() -> PlainTextResponse:
        return _geo_markdown("txt", geo.render_robots_txt(), ext="txt")

    @app.get("/sitemap.xml")
    def sitemap_xml() -> PlainTextResponse:
        return _geo_markdown("xml", geo.render_sitemap_xml())

    @app.get("/about.md")
    def about_md() -> PlainTextResponse:
        return _geo_markdown("md", geo.render_about_md())

    @app.get("/faq.md")
    def faq_md() -> PlainTextResponse:
        return _geo_markdown("md", geo.render_faq_md())

    @app.get("/compare.md")
    def compare_md() -> PlainTextResponse:
        return _geo_markdown("md", geo.render_compare_md())

    @app.get("/catalog.json")
    def catalog_json() -> dict[str, Any]:
        items = _geo_items()
        return geo.catalog_payload(items, full=True)

    def _public_image(name: str) -> FileResponse:
        site = settings.site_dir / name
        src = site if site.is_file() else geo.public_asset_src(name)
        if src is None or not src.is_file():
            raise HTTPException(404, "not found")
        media = "image/x-icon" if name.endswith(".ico") else "image/png"
        return FileResponse(src, media_type=media)

    @app.get("/favicon.ico")
    def favicon_ico() -> FileResponse:
        return _public_image("favicon.ico")

    @app.get("/favicon.png")
    def favicon_png() -> FileResponse:
        return _public_image("favicon.png")

    @app.get("/apple-touch-icon.png")
    def apple_touch_icon() -> FileResponse:
        return _public_image("apple-touch-icon.png")

    @app.get("/og.png")
    def og_png() -> FileResponse:
        return _public_image("og.png")

    def _geo_guard(request: Request) -> Optional[JSONResponse]:
        ip = _client_ip(request, settings.trusted_proxy_hops, settings.trusted_proxy_ips)
        if not app.state.geo_limiter.allow(ip):
            return JSONResponse(
                {"error": "rate_limited", "retry_after_s": 60},
                status_code=429,
                headers={"Retry-After": "60"},
            )
        return None

    @app.get("/api/geo/openapi.json")
    def api_geo_openapi() -> dict[str, Any]:
        return geo.render_geo_openapi()

    @app.get("/api/geo/skills")
    def api_geo_skills(
        request: Request,
        q: str = Query(""),
        scene: str = Query(""),
        limit: int = Query(20, ge=1, le=50),
        offset: int = Query(0, ge=0),
    ) -> dict[str, Any]:
        blocked = _geo_guard(request)
        if blocked is not None:
            return blocked
        page, total = geo.search_items(
            _geo_items(), query=q, scene=scene, limit=limit, offset=offset,
        )
        return {
            "brand": geo.BRAND,
            "canonical": geo.CANONICAL,
            "items": page,
            "total": total,
            "limit": min(limit, geo.API_MAX_LIMIT),
            "offset": offset,
            "q": q,
            "scene": scene,
        }

    @app.get("/api/geo/skills/{owner}/{repo}")
    def api_geo_skill(request: Request, owner: str, repo: str) -> dict[str, Any]:
        blocked = _geo_guard(request)
        if blocked is not None:
            return blocked
        item = geo.find_item(_geo_items(), owner, repo)
        if item is None:
            raise HTTPException(404, "skill not in the public catalog")
        return {"item": item}

    @app.get("/", response_class=HTMLResponse)
    def home() -> HTMLResponse:
        """登录后的落地页。

        有 publish-site 产物就直接把主站信息流发出去（同源、无出网），
        没有就退回这个 API 说明页。产物由 `python skillfeed.py publish-site
        --out <SKILLFEED_SITE_DIR>` 生成，本函数只读不写，
        模板生成器 feed_dashboard.py 不在本次改动范围内。
        """
        index = settings.site_dir / "index.html"
        if index.is_file():
            resp = HTMLResponse(index.read_text(encoding="utf-8"))
            resp.headers["Content-Security-Policy"] = CSP_SITE
            return resp
        nonce = secrets.token_urlsafe(16)
        html = (TEMPLATES / "home.html").read_text(encoding="utf-8")
        return html_response(html.replace("{{csp_nonce}}", nonce), nonce)

    @app.get("/feed.json")
    def feed_json(request: Request) -> JSONResponse:
        """同源的官方 feed 产物。

        取代「前端直连 github.io 拉 feed.json」：主站在国内域名上，
        跨境拉首屏数据时快时慢时不通。这个端点在门禁后面。
        发现流全量免费，不再按天切条；语料与门禁明细随产物返回。
        """
        path = settings.official_feed_file
        if not path.is_file():
            raise HTTPException(
                404,
                "本地 feed 产物不存在。先跑 "
                "`python skillfeed.py publish-site --out <SKILLFEED_SITE_DIR>`。",
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        items = [it for it in (data.get("items") or []) if isinstance(it, dict)]
        visible, quota = _apply_feed_quota(request, settings, items)
        data["items"] = visible
        if quota:
            data["quota"] = quota
            meta = dict(data.get("meta") or {})
            meta["quota"] = quota
            data["meta"] = meta
        return JSONResponse(data)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = "") -> Response:  # noqa: A002
        dest = _safe_next(next)
        if auth.session_user_id(request, settings) is not None:
            return RedirectResponse(dest, status_code=302)
        nonce = secrets.token_urlsafe(16)
        html = (TEMPLATES / "login.html").read_text(encoding="utf-8")
        # 只注入布尔开关和已消毒的 next。AppID 都不注入 —— 微信跳转是服务端
        # 拼的（/auth/wechat），前端不需要知道 AppID，更不需要知道任何 secret
        for key, value in (
            ("{{wechat_enabled}}", "1" if settings.wechat_configured else "0"),
            ("{{sms_enabled}}", "1" if settings.sms_configured else "0"),
            ("{{github_enabled}}", "1" if (
                settings.github_login_visible and settings.oauth_configured
            ) else "0"),
            ("{{dev_login}}", "1" if settings.dev_login_allowed else "0"),
            ("{{next}}", html_escape(dest, quote=True)),
            ("{{sms_cooldown}}", str(settings.sms_resend_cooldown_s)),
        ):
            html = html.replace(key, value)
        return html_response(html.replace("{{csp_nonce}}", nonce), nonce)

    @app.get("/publish", response_class=HTMLResponse)
    def publish_page(request: Request) -> HTMLResponse:
        uid = auth.session_user_id(request, settings)
        nonce = secrets.token_urlsafe(16)
        html = (TEMPLATES / "publish.html").read_text(encoding="utf-8")
        html = html.replace("{{logged_in}}", "1" if uid else "0")
        html = html.replace("{{public_url}}", settings.public_url)
        return html_response(html.replace("{{csp_nonce}}", nonce), nonce)

    def _admin_html(request: Request) -> HTMLResponse:
        uid = auth.require_user_id(request, settings)
        with db.db_session(settings.db_path) as conn:
            user = db.get_user(conn, uid)
        auth.require_operator(request, settings, (user or {}).get("login") or "")
        nonce = secrets.token_urlsafe(16)
        html = (TEMPLATES / "admin.html").read_text(encoding="utf-8")
        return html_response(html.replace("{{csp_nonce}}", nonce), nonce)

    @app.get("/op", response_class=HTMLResponse)
    @app.get("/op/", response_class=HTMLResponse)
    @app.get("/admin", response_class=HTMLResponse)
    @app.get("/admin/", response_class=HTMLResponse)
    def admin_page(request: Request) -> HTMLResponse:
        return _admin_html(request)

    @app.get("/p/{slug}")
    def public_card(slug: str) -> RedirectResponse:
        with db.db_session(settings.db_path) as conn:
            row = db.find_live_card(conn, slug)
        if not row or not row.get("public_id"):
            raise HTTPException(404, "没有这张已上架的卡片")
        return RedirectResponse(
            "/?card=" + quote(str(row["public_id"]), safe=""),
            status_code=302,
        )

    @app.get("/op/review", response_class=HTMLResponse)
    def review_page(request: Request) -> HTMLResponse:
        uid = auth.require_user_id(request, settings)
        with db.db_session(settings.db_path) as conn:
            user = db.get_user(conn, uid)
        auth.require_operator(request, settings, (user or {}).get("login") or "")
        nonce = secrets.token_urlsafe(16)
        html = (TEMPLATES / "review.html").read_text(encoding="utf-8")
        return html_response(html.replace("{{csp_nonce}}", nonce), nonce)

    # —— Auth ——
    @app.get("/auth/github")
    def auth_github(next: str = "") -> HTMLResponse:  # noqa: A002
        if not settings.oauth_configured:
            # 这里过去会在 dev_auth 时 302 到 /auth/dev-login（无凭据发 30 天会话）。
            # 那是个静默降级：接微信登录的改造期漏配一个环境变量，站点就变成
            # 「点一下就登进去」。现在一律报错，降级只能由显式访问 dev-login 触发。
            raise HTTPException(
                status_code=503,
                detail="未配置 GitHub OAuth（SKILLFEED_GITHUB_CLIENT_ID/SECRET）。",
            )
        # 与微信流程用同一套签名 state（见 server/auth.py 的说明）：
        # 原来这里是「随机串 + Cookie 比对」，能挡 CSRF 但不能证明这串是我们签的
        state = auth.issue_state(settings, "github")
        nonce = secrets.token_urlsafe(16)
        dest = auth.github_authorize_url(settings, state)
        resp = html_response(
            auth.oauth_handoff_html(dest, heading="正在前往 GitHub 登录…", nonce=nonce),
            nonce,
        )
        resp.headers["Cache-Control"] = "no-store"
        auth.set_state_cookie(resp, settings, "github", state)
        if next:
            resp.set_cookie(
                LOGIN_NEXT_COOKIE, _safe_next(next),
                max_age=settings.oauth_state_ttl_s, **auth.cookie_flags(settings),
            )
        return resp

    @app.get("/auth/github/callback")
    @app.get("/auth/callback")
    async def auth_callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
        if not code:
            raise HTTPException(400, "missing code")
        cookie = request.cookies.get(auth.STATE_COOKIE["github"]) or ""
        if not auth.verify_state(settings, "github", state, cookie):
            raise HTTPException(400, "bad oauth state")
        gh = await auth.exchange_github_code(settings, code)
        uid = auth.session_user_id(request, settings)
        try:
            with db.db_session(settings.db_path) as conn:
                if uid:
                    user = db.attach_github(
                        conn, uid,
                        github_id=int(gh["id"]),
                        login=gh.get("login") or "",
                        avatar_url=gh.get("avatar_url") or "",
                        name=gh.get("name") or "",
                    )
                else:
                    user = db.upsert_user(
                        conn,
                        github_id=int(gh["id"]),
                        login=gh.get("login") or "",
                        avatar_url=gh.get("avatar_url") or "",
                        name=gh.get("name") or "",
                    )
        except db.IdentityBound:
            dest = "/login?err=identity_taken" if uid is None else "/?tab=me&bind=taken"
            resp = RedirectResponse(dest, status_code=302)
            auth.clear_state_cookie(resp, "github")
            return resp
        dest = _safe_next(
            request.cookies.get(LOGIN_NEXT_COOKIE) or ("/?tab=me" if uid else "/publish")
        )
        resp = RedirectResponse(dest, status_code=302)
        auth.set_session_cookie(resp, settings, int(user["id"]), user["login"])
        auth.clear_state_cookie(resp, "github")
        resp.delete_cookie(LOGIN_NEXT_COOKIE, path="/")
        return resp

    # —— 微信服务号网页授权（主站 V1 的主登录方式）——
    @app.get("/auth/wechat")
    def auth_wechat(next: str = "") -> HTMLResponse:  # noqa: A002
        if not settings.wechat_configured:
            raise HTTPException(
                status_code=503,
                detail="未配置微信服务号（SKILLFEED_WECHAT_APP_ID / "
                       "SKILLFEED_WECHAT_APP_SECRET）。",
            )
        state = auth.issue_state(settings, "wechat")
        nonce = secrets.token_urlsafe(16)
        dest = auth.wechat_authorize_url(settings, state)
        resp = html_response(
            auth.oauth_handoff_html(dest, heading="正在前往微信登录…", nonce=nonce),
            nonce,
        )
        resp.headers["Cache-Control"] = "no-store"
        auth.set_state_cookie(resp, settings, "wechat", state)
        # 登录成功后回到用户原本想去的地方。放 Cookie 而不是塞进 state：
        # state 要参与签名比对，往里拼可变内容就得考虑分隔符转义，没必要
        resp.set_cookie(
            LOGIN_NEXT_COOKIE, _safe_next(next),
            max_age=settings.oauth_state_ttl_s, **auth.cookie_flags(settings),
        )
        return resp

    @app.get("/auth/wechat/callback")
    async def auth_wechat_callback(
        request: Request, code: str = "", state: str = "",
    ) -> RedirectResponse:
        if not settings.wechat_configured:
            raise HTTPException(503, "未配置微信服务号")
        if not code:
            raise HTTPException(400, "missing code")
        # state 的服务端校验：签名有效 + 未过期 + 与 HttpOnly Cookie 一致。
        # 三条全在服务端判定，回传值本身不被信任
        cookie = request.cookies.get(auth.STATE_COOKIE["wechat"]) or ""
        if not auth.verify_state(settings, "wechat", state, cookie):
            raise HTTPException(400, "bad oauth state")
        token = await auth.exchange_wechat_code(settings, code)
        info: dict[str, Any] = {}
        if settings.wechat_scope == "snsapi_userinfo":
            # 拿不到昵称头像不该让登录失败：openid 已经足够认人
            info = await auth.fetch_wechat_userinfo(
                settings, str(token.get("access_token") or ""), str(token["openid"]),
            )
        uid = auth.session_user_id(request, settings)
        try:
            with db.db_session(settings.db_path) as conn:
                if uid:
                    user = db.attach_wechat(
                        conn, uid,
                        openid=str(token["openid"]),
                        unionid=str(token.get("unionid") or info.get("unionid") or ""),
                        nickname=str(info.get("nickname") or ""),
                        avatar_url=str(info.get("headimgurl") or ""),
                    )
                else:
                    user = db.upsert_wechat_user(
                        conn,
                        openid=str(token["openid"]),
                        unionid=str(token.get("unionid") or info.get("unionid") or ""),
                        nickname=str(info.get("nickname") or ""),
                        avatar_url=str(info.get("headimgurl") or ""),
                    )
        except db.IdentityBound:
            dest = "/login?err=identity_taken" if uid is None else "/?tab=me&bind=taken"
            resp = RedirectResponse(dest, status_code=302)
            auth.clear_state_cookie(resp, "wechat")
            return resp
        dest = _safe_next(
            request.cookies.get(LOGIN_NEXT_COOKIE) or ("/?tab=me" if uid else "/")
        )
        resp = RedirectResponse(dest, status_code=302)
        auth.set_session_cookie(resp, settings, int(user["id"]), user["login"])
        auth.clear_state_cookie(resp, "wechat")
        resp.delete_cookie(LOGIN_NEXT_COOKIE, path="/")
        return resp

    # —— 手机号验证码兜底（小红书 / 抖音内置浏览器里微信授权走不通时用）——
    @app.post("/auth/sms/send")
    async def auth_sms_send(request: Request, body: SmsSendBody) -> dict[str, Any]:
        phone = auth.normalize_phone(body.phone)
        if not phone:
            raise HTTPException(400, "手机号格式不正确")
        if not settings.sms_configured:
            raise HTTPException(503, "短信通道未配置")
        ip = _client_ip(request, settings.trusted_proxy_hops, settings.trusted_proxy_ips)
        # 进程内滑动窗口：同手机号频次 + 同 IP 频次
        hit = app.state.sms_limiter.allow_send(phone=phone, ip=ip)
        if hit == "phone":
            raise HTTPException(429, "该手机号请求过于频繁，请稍后再试")
        if hit == "ip":
            raise HTTPException(429, "请求过于频繁，请稍后再试")

        code = auth.new_sms_code()
        # 库里的重发冷却，和上面那道并存：滑动窗口在进程内，重启就清零；
        # 冷却读的是 sms_codes.created_at，重启后依然有效
        with db.db_session(settings.db_path) as conn:
            db.prune_sms_codes(conn)
            current = db.get_sms_code(conn, phone)
            cooling = bool(
                current
                and _age_s(current["created_at"]) is not None
                and _age_s(current["created_at"]) < settings.sms_resend_cooldown_s
            )
            if not cooling:
                db.put_sms_code(
                    conn,
                    phone=phone,
                    # 入库的是 HMAC 摘要，明文只活在这个函数的栈上
                    code_hash=auth.hash_sms_code(settings.session_secret, phone, code),
                    ttl_s=settings.sms_code_ttl_s,
                )
        if cooling:
            raise HTTPException(429, f"请求过于频繁，请 {settings.sms_resend_cooldown_s} 秒后再试")

        try:
            # 出网放在事务外：别让一次网关超时把 SQLite 的写锁按住
            await sms.send_code(settings, phone, code)
        except sms.SmsError as e:
            # 发送失败就把码作废，否则用户会被自己的冷却锁在门外
            with db.db_session(settings.db_path) as conn:
                db.drop_sms_code(conn, phone)
            raise HTTPException(502, "短信发送失败，请稍后重试") from e
        # 响应体里没有验证码，也没有任何凭据 —— 只有前端做倒计时需要的两个数
        return {
            "ok": True,
            "expires_in": settings.sms_code_ttl_s,
            "cooldown_s": settings.sms_resend_cooldown_s,
        }

    @app.post("/auth/sms/verify")
    def auth_sms_verify(request: Request, body: SmsVerifyBody) -> JSONResponse:
        phone = auth.normalize_phone(body.phone)
        code = (body.code or "").strip()
        if not phone or len(code) != 6 or not code.isdigit():
            raise HTTPException(400, "手机号或验证码格式不正确")
        ip = _client_ip(request, settings.trusted_proxy_hops, settings.trusted_proxy_ips)
        # 跨手机号的爆破由这道挡；单个码的猜测次数由 sms_codes.attempts 挡
        if not app.state.sms_limiter.allow_verify(ip=ip):
            raise HTTPException(429, "尝试次数过多，请稍后再试")

        # ⚠️ 不在 db_session 里抛异常：db_session 的异常分支会 rollback，
        # 那样失败计数 +1 会被一起回滚掉，验证码就变成可以无限次猜。
        # 所以这里先把结论算出来（并提交），再在事务外决定抛什么。
        error = ""
        user: Optional[dict[str, Any]] = None
        with db.db_session(settings.db_path) as conn:
            row = db.get_sms_code(conn, phone)
            expired = bool(row and (_age_s(row["expires_at"]) or 0) > 0)
            if not row or expired:
                if row:
                    db.drop_sms_code(conn, phone)
                error = "expired"
            elif int(row["attempts"]) >= settings.sms_max_attempts:
                db.drop_sms_code(conn, phone)
                error = "too_many"
            elif not hmac.compare_digest(
                auth.hash_sms_code(settings.session_secret, phone, code),
                str(row["code_hash"]),
            ):
                if db.bump_sms_attempt(conn, phone) >= settings.sms_max_attempts:
                    db.drop_sms_code(conn, phone)
                error = "bad_code"
            else:
                # 单次有效：验证通过立刻删行，同一个码不可能被用第二次
                db.drop_sms_code(conn, phone)
                uid = auth.session_user_id(request, settings)
                if uid:
                    try:
                        user = db.attach_phone(conn, uid, phone=phone)
                    except db.IdentityBound:
                        error = "taken"
                else:
                    user = db.upsert_phone_user(conn, phone=phone)

        if error == "expired":
            raise HTTPException(400, "验证码已过期，请重新获取")
        if error == "too_many":
            raise HTTPException(429, "验证码错误次数过多，请重新获取")
        if error == "bad_code":
            raise HTTPException(400, "验证码不正确")
        if error == "taken":
            raise HTTPException(409, "这个手机号已经绑在别的账号上")
        assert user is not None
        resp = JSONResponse({
            "ok": True,
            "user": db.user_public(user),
            "next": _safe_next(body.next),
        })
        auth.set_session_cookie(resp, settings, int(user["id"]), user["login"])
        return resp

    @app.get("/auth/dev-login")
    def auth_dev_login(request: Request, login: str = "dev-user") -> RedirectResponse:
        if not settings.dev_login_allowed:
            raise HTTPException(404, "dev auth disabled")
        safe_login = (login[:39] or "dev-user")
        with db.db_session(settings.db_path) as conn:
            user = db.upsert_user(
                conn,
                # 过去写死 github_id=1：所有 dev 登录复用同一行 users，
                # 一个 GET 就能改掉那行的用户名；而且 1 是合法的真实 GitHub id，
                # 可能撞上真人账号。改成由 login 派生的负数，与真实 id 空间不相交。
                # 用 blake2b 而不是内置 hash()：后者按进程随机化，重启就换一行用户。
                github_id=-1 - int.from_bytes(
                    hashlib.blake2b(safe_login.encode("utf-8"), digest_size=4).digest(),
                    "big",
                ),
                login=safe_login,
                avatar_url="",
                name="Dev User",
            )
        resp = RedirectResponse("/publish", status_code=302)
        auth.set_session_cookie(resp, settings, int(user["id"]), user["login"])
        return resp

    @app.post("/auth/logout")
    def auth_logout() -> JSONResponse:
        resp = JSONResponse({"ok": True})
        auth.clear_session_cookie(resp, settings)
        return resp

    @app.get("/auth/me")
    def auth_me(request: Request) -> dict[str, Any]:
        """当前登录用户。**这个端点本身免登录**（在门禁豁免表里）。

        必须免登录：前端要用它回答「我登了没有」。如果它也 302 到登录页，
        前端就只能靠「请求别的接口看有没有被重定向」来推断登录态，
        每次判断都要多打一个可能重定向的请求。
        未登录时返回 200 + `user: null`，不是 401。
        """
        base = {
            "oauth": settings.oauth_configured,
            "wechat": settings.wechat_configured,
            "sms": settings.sms_configured,
            "dev_auth": settings.dev_auth,
            "require_login": settings.require_login,
            "login_url": "/login",
        }
        uid = auth.session_user_id(request, settings)
        if uid is None:
            return {"user": None, "quota": None, **base}
        quota = None
        with db.db_session(settings.db_path) as conn:
            user = db.get_user(conn, uid)
            if user:
                quota = entitlement.quota_status(
                    conn, user, limit=settings.free_daily_feed_items,
                )
                # 账号收藏/点赞的 full_name 数组：跨设备聚合，给前端「查看收藏」
                # 做列表与计数同源，避免「计数读云端、列表读本机」两边对不上。
                saved = db.user_saved_full_names(conn, uid)
                liked = db.user_liked_full_names(conn, uid)
        return {
            "user": db.user_public(user) if user else None,
            "quota": quota,
            "saved": saved,
            "liked": liked,
            **base,
        }

    @app.get("/api/me/export")
    def api_me_export(request: Request) -> JSONResponse:
        uid = auth.require_user_id(request, settings)
        with db.db_session(settings.db_path) as conn:
            payload = db.export_account(conn, uid)
        resp = JSONResponse(payload)
        resp.headers["Content-Disposition"] = 'attachment; filename="skillfeeder-account.json"'
        return resp

    @app.post("/api/account/activate")
    def activate_subscription(request: Request, body: ActivateBody) -> dict[str, Any]:
        """用激活码兑换订阅。收款通道未接前，这是权益送达的第一版。"""
        uid = auth.session_user_id(request, settings)
        if uid is None:
            raise HTTPException(401, "login required")
        code = (body.code or "").strip()
        if not code or code not in settings.activation_codes:
            raise HTTPException(400, "激活码无效")
        until = None
        if settings.subscriber_days > 0:
            until = (
                datetime.now(timezone.utc) + timedelta(days=settings.subscriber_days)
            ).isoformat()
        with db.db_session(settings.db_path) as conn:
            db.set_user_plan(conn, uid, "subscriber", until)
            user = db.get_user(conn, uid)
            quota = entitlement.quota_status(
                conn, user, limit=settings.free_daily_feed_items,
            ) if user else None
        return {
            "ok": True,
            "user": db.user_public(user) if user else None,
            "quota": quota,
        }

    def _pay_error(exc: pay.PayError) -> HTTPException:
        return HTTPException(exc.status, exc.detail)

    @app.get("/api/pay/catalog")
    def pay_catalog(request: Request) -> dict[str, Any]:
        uid = auth.session_user_id(request, settings)
        if uid is None:
            raise HTTPException(401, "login required")
        return {
            "items": [pay.sku_public(s) for s in pay.catalog(settings).values()],
            "wechat_pay": settings.wechat_pay_configured,
            "dev_notify": settings.dev_mode,
        }

    @app.post("/api/pay/create")
    def pay_create(request: Request, body: PayCreateBody) -> dict[str, Any]:
        uid = auth.session_user_id(request, settings)
        if uid is None:
            raise HTTPException(401, "login required")
        try:
            with db.db_session(settings.db_path) as conn:
                order = pay.create_order(
                    conn, user_id=uid, sku_id=body.sku, settings=settings,
                )
        except pay.PayError as e:
            raise _pay_error(e) from e
        return {"ok": True, "order": pay.order_public(order)}

    @app.get("/api/pay/orders")
    def pay_orders(request: Request) -> dict[str, Any]:
        uid = auth.session_user_id(request, settings)
        if uid is None:
            raise HTTPException(401, "login required")
        with db.db_session(settings.db_path) as conn:
            rows = db.list_orders_for_user(conn, uid)
        return {"orders": [pay.order_public(r) for r in rows]}

    @app.post("/api/pay/dev-notify")
    def pay_dev_notify(request: Request, body: PayDevNotifyBody) -> dict[str, Any]:
        """假到账。只在 SKILLFEED_DEV=1 时存在，且只能操作自己的单。"""
        if not settings.dev_mode:
            raise HTTPException(404, "dev pay notify disabled")
        uid = auth.session_user_id(request, settings)
        if uid is None:
            raise HTTPException(401, "login required")
        trade_no = (body.out_trade_no or "").strip()
        txn = (body.transaction_id or "").strip() or f"dev-{trade_no}"
        try:
            with db.db_session(settings.db_path) as conn:
                order = db.get_order_by_trade_no(conn, trade_no)
                if order is None:
                    raise pay.PayError(404, "订单不存在")
                if int(order["user_id"]) != int(uid):
                    raise pay.PayError(403, "只能开通自己的订单")
                paid, replay = pay.apply_paid_notify(
                    conn,
                    out_trade_no=trade_no,
                    provider_txn_id=txn,
                    amount_fen=int(order["amount_fen"]),
                    settings=settings,
                )
                user = db.get_user(conn, uid)
                quota = entitlement.quota_status(
                    conn, user, limit=settings.free_daily_feed_items,
                ) if user else None
        except pay.PayError as e:
            raise _pay_error(e) from e
        return {
            "ok": True,
            "replay": replay,
            "order": pay.order_public(paid),
            "user": db.user_public(user) if user else None,
            "quota": quota,
        }

    @app.post("/api/pay/wechat/notify")
    async def pay_wechat_notify(request: Request) -> JSONResponse:
        raw = await request.body()
        try:
            payload = pay.verify_wechat_notify(raw, request.headers, settings)
            with db.db_session(settings.db_path) as conn:
                pay.apply_paid_notify(
                    conn,
                    out_trade_no=str(payload.get("out_trade_no") or ""),
                    provider_txn_id=str(payload.get("transaction_id") or ""),
                    amount_fen=payload.get("amount_fen"),
                    settings=settings,
                )
        except pay.PayError as e:
            return JSONResponse(
                {"code": "FAIL", "message": e.detail},
                status_code=e.status,
            )
        return JSONResponse({"code": "SUCCESS", "message": "成功"})

    # —— Feed ——
    @app.get("/api/feed")
    async def api_feed(
        request: Request,
        limit: int = Query(40, ge=1, le=100),
        offset: int = Query(0, ge=0),
        source: str = Query("all", pattern="^(all|ugc|official)$"),
        device_id: str = Query("", description="建议改用 X-Device-Id 请求头，query 会进访问日志"),
        session_id: str = Query(""),
        q: str = Query(""),
        scene: str = Query(""),
        scene_l2: str = Query(""),
        debug: int = Query(0),
        unlock: int = Query(1, ge=0, le=1),
    ) -> dict[str, Any]:
        cfg = app.state.ranking_config
        device_id = _device_id(request, device_id)
        ugc_items: list[dict] = []
        with db.db_session(settings.db_path) as conn:
            posts = db.list_published_posts(conn, limit=200, offset=0)
            ugc_items = [ugc.post_to_feed_item(p) for p in posts]

        official: list[dict] = []
        if source in ("all", "official"):
            # 有显式 URL 就走 URL（部署方可以指到国内同源地址或内网地址），
            # 没有就读服务器本地的 publish-site 产物。默认不再是 github.io：
            # 主站在国内域名上，跨境拉首屏数据不可靠
            if settings.official_feed_url:
                official = await ugc.load_official_items(settings.official_feed_url)
            else:
                official = ugc.load_official_items_from_file(settings.official_feed_file)

        # UGC 置顶是既有产品行为，排序在各自块内进行，不跨块打散
        if source == "ugc":
            blocks = [ugc_items]
        elif source == "official":
            blocks = [official]
        else:
            seen = {i.get("full_name") for i in ugc_items if i.get("full_name")}
            rest = [i for i in official if not (i.get("full_name") and i.get("full_name") in seen)]
            blocks = [ugc_items, rest]

        profile = None
        stats: dict = {}
        issued_token = ""
        if device_id:
            lookup = {
                (i.get("id") or i.get("full_name") or ""): i
                for block in blocks for i in block
            }
            # 「不感兴趣」的会话内回声：比持久压制宽，但只活到会话过期。
            # 见 ranking_service.SessionOrderCache.note_not_interested
            echo = app.state.order_cache.session_echo(device_id, session_id)
            with db.db_session(settings.db_path) as conn:
                if db.touch_device(conn, device_id):
                    issued_token = auth.device_token(settings.session_secret, device_id)
                profile = ranking_service.load_profile(
                    conn, device_id, config=cfg, item_lookup=lookup,
                    extra_suppress=echo,
                )
                stats = ranking_service.load_item_stats(conn)

        sig = ranking_service.filter_signature(
            q=q, scene=scene, scene_l2=scene_l2, source=source,
        )
        cache_key = ranking_service.cache_key(device_id, session_id, sig)
        cached = app.state.order_cache.get(cache_key) if (device_id and session_id) else None

        ranked: list[dict] = []
        for block in blocks:
            if not block:
                continue
            ordered = ranking.rank_feed(
                block,
                profile=profile,
                stats=stats,
                gstats=ranking.build_global_stats(stats, block) if stats else None,
                config=cfg,
                query=q,
                scene_filter=scene,
                scene_l2_filter=scene_l2,
                session_seed=f"{device_id}:{session_id}",
            )
            ranked.extend(ordered)

        # 会话内顺序固化：翻页/刷新只对已算好的顺序切片，不重排。
        # 收到 not_interested 后缓存顺序会被截断到「已交付的高水位」，
        # 于是这里 cached 只覆盖用户已经看过的那一段，后面的部分按新画像重排——
        # 已看过的卡不会移位，还没看到的立刻生效。
        if cached:
            ranked = ranking_service.apply_cached_order(ranked, cached)
        if device_id and session_id:
            app.state.order_cache.put(
                cache_key,
                [it.get("id") or it.get("full_name") or "" for it in ranked],
            )
            app.state.order_cache.mark_served(cache_key, offset + limit)

        visible, quota = _apply_feed_quota(
            request, settings, ranked, claim=bool(unlock),
        )
        total = len(visible)
        page = visible[offset: offset + limit]
        if not debug:
            for it in page:
                it.pop("rank_debug", None)
        for it in page:
            for k in ("_affinity", "_focus_hit", "_relevance"):
                it.pop(k, None)

        out: dict[str, Any] = {
            "items": page,
            "total": total,
            "ugc_count": len(ugc_items) if source != "official" else 0,
            "official_count": len(official),
            "quota": quota,
            "generated_mode": "api-merge",
            "session_id": session_id,
            "ranking_mode": (
                "search" if q.strip()
                else ("personalized" if (profile and profile.events) else "global")
            ),
            "me": None,
        }
        # 凭据只在首次注册时返回一次，客户端要存下来；并档时用它证明设备归属
        if issued_token:
            out["device_token"] = issued_token
        return out

    # —— 埋点 ——
    @app.post("/api/events")
    def api_events(request: Request, body: EventsBody) -> dict[str, Any]:
        device_id = _device_id(request, body.device_id)
        session_id = (body.session_id or "").strip()[:64]
        if not device_id or not session_id:
            raise HTTPException(400, "device_id and session_id are required")
        incoming = list(body.events or [])
        events = incoming[:MAX_EVENTS_PER_REQUEST]
        pre_rejected: dict[str, int] = {}
        if len(incoming) > len(events):
            pre_rejected["truncated"] = len(incoming) - len(events)

        # 超限静默丢弃：返回 429 等于告诉刷量的人阈值在哪。
        # 但静默 ≠ 不记账：命中数进指标，否则「排序信号在悄悄变少」这件事
        # 又会变成只能靠人工翻文件发现
        allowed = app.state.event_limiter.allow(
            ip=_client_ip(
                request, settings.trusted_proxy_hops, settings.trusted_proxy_ips,
            ),
            device_id=device_id,
            count=max(1, len(events)),
        )
        if allowed < len(events):
            pre_rejected["ratelimited"] = len(events) - allowed
        events = events[:allowed]
        if not events:
            app.state.ingest_metrics.record(rejected=pre_rejected)
            return {"ok": True, "accepted": 0, "deduped": 0}

        with db.db_session(settings.db_path) as conn:
            created = db.touch_device(conn, device_id)
            uid = auth.session_user_id(request, settings)
            if uid:
                db.link_device_user(conn, device_id, uid)
            result = ranking_service.ingest_events(
                conn, device_id, session_id, events,
                config=app.state.ranking_config,
                session_state=app.state.order_cache,
            )
        rejected = dict(result.get("rejected") or {})
        for reason, n in pre_rejected.items():
            rejected[reason] = rejected.get(reason, 0) + n
        app.state.ingest_metrics.record(
            accepted=result["accepted"],
            deduped=result["deduped"],
            rejected=rejected,
            by_action=result.get("by_action"),
        )
        out: dict[str, Any] = {
            "ok": True,
            "accepted": result["accepted"],
            "deduped": result["deduped"],
            # 前端据此自查：拒了多少、为什么。契约里字段名写错时这里会直接说
            "rejected": sum(rejected.values()),
            "rejected_by_reason": {k: v for k, v in rejected.items() if v},
        }
        if created:
            out["device_token"] = auth.device_token(settings.session_secret, device_id)
        return out

    @app.get("/api/events/health")
    def api_events_health(request: Request) -> dict[str, Any]:
        """埋点摄入健康。ops 门禁，见 require_ops。

        `stale` 就是为了「feedback.jsonl 一个多月零新增没人发现」这件事存在的：
        接一个定时器轮询它，链路断了当天就会响，而不是等到有人想起来查。
        """
        require_ops(request)
        with db.db_session(settings.db_path) as conn:
            summary = db.ingest_summary(conn)
        stale_after = float(app.state.ranking_config["ingest"]["stale_after_s"])
        age = metrics.staleness(summary.get("last_event_at"))
        return {
            "ok": True,
            **summary,
            "last_event_age_s": round(age, 1) if age is not None else None,
            "stale_after_s": stale_after,
            # 一条都没有 ≠ 很久没有：前者是没开张，后者是链路断了
            "stale": bool(age is not None and age > stale_after),
            "empty": summary["events_total"] == 0,
            "process": app.state.ingest_metrics.snapshot(),
        }

    @app.get("/api/stats/items")
    def api_stats_items(request: Request) -> dict[str, Any]:
        """全站曝光/点击导出，给 build 期把「站内热度」烧进静态 feed.json 用。

        只有聚合量，没有 device_id / session_id / 任何单用户轨迹。
        走 ops 门禁的原因不是隐私，是这份数据能让刷量的人验证自己刷成功没有。
        """
        require_ops(request)
        with db.db_session(settings.db_path) as conn:
            rows = db.item_stats_rows(conn)
        return {"ok": True, "generated_at": _utc_now_iso(), "items": rows}

    @app.get("/api/profile/reactions")
    def api_profile_reactions(
        request: Request,
        device_id: str = Query(""),
        limit: int = Query(200, ge=1, le=500),
    ) -> dict[str, Any]:
        """设备自己点过的：赞过的 / 收藏的 / 打开过的，三条互不混淆的列表。

        点赞和收藏在这里就是两条不同的流水，而不是同一个 `useful`。
        用户点了赞却无处可查，那个动作对他就是纯粹的空转——只有我们拿到信号，
        他什么都没得到。这个端点是「我的」面板的数据源。

        要 device_token：device_id 是客户端自铸的，只凭它就能读，
        等于知道别人 device_id 就能翻他的浏览记录。凭据只在首次注册时下发过，
        与 /api/profile/claim 用的是同一枚。
        """
        did = _device_id(request, device_id)
        token = (request.headers.get("x-device-token") or "").strip()
        if not did:
            raise HTTPException(400, "device_id is required")
        if not auth.verify_device_token(settings.session_secret, did, token):
            raise HTTPException(403, "invalid device_token for this device_id")
        with db.db_session(settings.db_path) as conn:
            target = db.resolve_device(conn, did)
            rows = db.load_device_reactions(conn, target, limit=limit)
        buckets: dict[str, list[dict]] = {"liked": [], "saved": [], "opened": []}
        name = {"useful": "liked", "save": "saved", "open_github": "opened"}
        for r in rows:
            bucket = name.get(r.pop("action", ""), "")
            if bucket:
                buckets[bucket].append(r)
        return {"ok": True, "device_id": target, **buckets}

    @app.post("/api/profile/claim")
    def api_profile_claim(request: Request, body: ClaimBody) -> dict[str, Any]:
        """登录后把匿名设备画像并档到账号。登录能力落地前这里会 401。"""
        uid = auth.require_user_id(request, settings)
        device_id = _device_id(request, body.device_id)
        if not device_id:
            raise HTTPException(400, "device_id is required")
        # 只有登录态还不够：device_id 是客户端自铸的，知道别人的就能把他的
        # 匿名画像并进自己账号（并且 merged_into 会把受害者后续请求也导向你，
        # 等于接管了他的个性化）。所以要校验首次注册时下发的那枚服务端签名凭据。
        token = (body.device_token or request.headers.get("x-device-token") or "").strip()
        if not auth.verify_device_token(settings.session_secret, device_id, token):
            raise HTTPException(403, "invalid device_token for this device_id")
        with db.db_session(settings.db_path) as conn:
            result = ranking_service.claim_device(conn, device_id, uid)
        app.state.order_cache.clear()
        return result

    # —— Posts ——
    def _submit_post(
        uid: int, title: str, github_url: str, description: str,
        request: Optional[Request] = None,
    ) -> dict[str, Any]:
        with db.db_session(settings.db_path) as conn:
            user = db.get_user(conn, uid)
            if not user:
                raise HTTPException(401, "login required")
            if (user.get("status") or "active") != "active":
                raise HTTPException(403, "账号不可用，不能投稿")
            if db.count_posts_today(conn, uid) >= settings.submit_per_day:
                raise HTTPException(400, f"今天不能再交（限额 {settings.submit_per_day}）")
            try:
                prepared = ugc.prepare_post_payload(
                    title=title,
                    github_url=github_url,
                    description=description,
                    author_login=user.get("login") or "",
                )
            except ValueError as e:
                raise HTTPException(400, str(e)) from e
            if not (prepared.get("github_meta") or {}).get("owner_ok"):
                raise HTTPException(400, "这不是你的仓库，不能认领")
            taken = db.find_post_by_coord(
                conn, prepared["full_name"], prepared["skill_path"],
            )
            if taken:
                raise HTTPException(400, "这条已被认领")
            post = db.create_post(conn, uid, prepared)
            device_id = ((request.headers.get("x-device-id") if request else "") or "").strip()[:64]
            if device_id:
                db.link_device_user(conn, device_id, uid)
                ranking_service.ingest_events(
                    conn, device_id, "publish",
                    [{
                        "action": "publish_submit",
                        "item_key": post.get("public_id") or post.get("full_name") or "",
                        "source": "form",
                        "client_ts": datetime.now(timezone.utc).isoformat(),
                    }],
                    config=app.state.ranking_config,
                )
        notify.notify_pending_review(settings, post)
        return post

    @app.post("/api/posts")
    async def api_create_post(request: Request, body: PostCreate) -> dict[str, Any]:
        uid = auth.require_user_id(request, settings)
        post = _submit_post(uid, body.title, body.github_url, body.description, request)
        return {"ok": True, "post": post, "status": post.get("status")}

    @app.post("/api/posts/form")
    async def api_create_post_form(
        request: Request,
        title: str = Form(""),
        github_url: str = Form(""),
        description: str = Form(""),
        body_md: str = Form(""),
    ) -> RedirectResponse:
        del body_md
        uid = auth.require_user_id(request, settings)
        _submit_post(uid, title, github_url, description, request)
        return RedirectResponse("/publish?ok=1", status_code=303)

    def _op_user(request: Request) -> tuple[int, dict[str, Any]]:
        uid = auth.require_user_id(request, settings)
        with db.db_session(settings.db_path) as conn:
            user = db.get_user(conn, uid)
        if not user:
            raise HTTPException(401, "login required")
        auth.require_operator(request, settings, user.get("login") or "")
        return uid, user

    @app.get("/api/site-config")
    def api_site_config() -> dict[str, Any]:
        with db.db_session(settings.db_path) as conn:
            return {"ok": True, "config": db.list_site_settings(conn, public_only=True)}

    @app.get("/api/op/stats")
    def api_op_stats(request: Request) -> dict[str, Any]:
        _op_user(request)
        with db.db_session(settings.db_path) as conn:
            stats = db.op_stats(conn)
        stats["backup"] = backup.backup_status(settings.backup_dir)
        return stats

    @app.post("/api/op/backup")
    def api_op_backup(request: Request) -> dict[str, Any]:
        _op_user(request)
        path = backup.backup_sqlite(
            settings.db_path, settings.backup_dir, keep=settings.backup_keep,
        )
        return {"ok": True, "file": path.name, **backup.backup_status(settings.backup_dir)}

    @app.get("/api/op/settings")
    def api_op_settings_get(request: Request) -> dict[str, Any]:
        _op_user(request)
        with db.db_session(settings.db_path) as conn:
            cfg = db.list_site_settings(conn, public_only=False)
        return {"ok": True, "config": cfg, "webhook_on": bool(cfg.get("review_webhook"))}

    @app.post("/api/op/settings")
    def api_op_settings_set(request: Request, body: SiteSettingsBody) -> dict[str, Any]:
        _op_user(request)
        updates = {
            "slogan": (body.slogan or "").strip()[:80],
            "search_placeholder": (body.search_placeholder or "").strip()[:80],
            "logo_url": (body.logo_url or "").strip()[:400],
            "review_webhook": (body.review_webhook or "").strip()[:500],
        }
        if updates["logo_url"] and not updates["logo_url"].startswith(("https://", "/")):
            raise HTTPException(400, "logo 只接受 https 或站内路径")
        if updates["review_webhook"] and not updates["review_webhook"].startswith("https://"):
            raise HTTPException(400, "webhook 必须是 https")
        with db.db_session(settings.db_path) as conn:
            for key, value in updates.items():
                db.set_site_setting(conn, key, value)
            cfg = db.list_site_settings(conn, public_only=False)
        return {"ok": True, "config": cfg, "webhook_on": bool(cfg.get("review_webhook"))}

    @app.get("/api/op/queue")
    def api_op_queue(
        request: Request, status: str = Query("pending"),
    ) -> dict[str, Any]:
        _op_user(request)
        with db.db_session(settings.db_path) as conn:
            rows = db.list_moderation_queue(conn, status=status)
        return {"posts": rows}

    @app.get("/api/op/queue.csv")
    def api_op_queue_csv(request: Request, status: str = Query("pending")) -> Response:
        _op_user(request)
        with db.db_session(settings.db_path) as conn:
            rows = db.list_moderation_queue(conn, status=status)
        def cell(v: Any) -> str:
            return '"' + str(v or "").replace('"', '""') + '"'

        lines = [
            "id,title,copy,github_url,skill_path,author_login,trust_level,approved_count,submitted_at"
        ]
        for r in rows:
            lines.append(",".join(cell(r.get(k)) for k in (
                "id", "title", "description", "github_url", "skill_path",
                "author_login", "trust_level", "approved_count", "created_at",
            )))
        return Response(
            "\n".join(lines) + "\n",
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=skillfeeder-queue.csv"},
        )

    @app.get("/api/op/journeys")
    def api_op_journeys(
        request: Request,
        hours: int = Query(72),
        limit: int = Query(40),
    ) -> dict[str, Any]:
        _op_user(request)
        with db.db_session(settings.db_path) as conn:
            return {
                "ok": True,
                "kpis": db.journey_kpis(conn, hours=hours),
                "sessions": db.list_journey_sessions(conn, hours=hours, limit=limit),
            }

    def _push_ugc_to_bitable(post: dict[str, Any]) -> None:
        """审核通过的 UGC 帖子自动推送到飞书底表（来源=用户上传）。"""
        import os
        import subprocess
        import tempfile

        fn = post.get("full_name") or ""
        if not fn:
            return
        tgt_path = Path.home() / ".skill-feed" / "bitable_export" / "target.json"
        if not tgt_path.is_file():
            return
        try:
            tgt = json.loads(tgt_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        bt = tgt.get("base_token")
        tid = tgt.get("table_id")
        if not bt or not tid:
            return
        # 构造底表记录
        desc = (post.get("description") or "")[:500]
        owner = fn.split("/")[0] if "/" in fn else ""
        record = {
            "名称": (post.get("title") or fn.split("/")[-1])[:200],
            "仓库全名": fn,
            "来源": "用户上传",
            "发布人": post.get("author_login") or owner,
            "发布时间": "",
            "GitHub链接": post.get("github_url") or f"https://github.com/{fn}",
            "分类": "其他",
            "二级分类": post.get("scene_l2_label") or "",
            "关键词": desc[:120],
            "描述": desc,
            "收录时间": (post.get("created_at") or "")[:16],
            "数据池": "主Feed",
        }
        # 写临时文件并调 lark-cli
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump({"create_records": [record]}, f, ensure_ascii=False)
            tmp = f.name
        try:
            subprocess.run(
                ["lark-cli", "base", "+record-batch-create",
                 "--as", "user", "--base-token", bt,
                 "--table-id", tid, "--json", f"@{Path(tmp).name}"],
                capture_output=True, text=True, encoding="utf-8",
                timeout=30, cwd=str(Path(tmp).parent),
            )
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    @app.get("/api/op/journeys.csv")
    def api_op_journeys_csv(
        request: Request, hours: int = Query(72),
    ) -> Response:
        _op_user(request)
        with db.db_session(settings.db_path) as conn:
            rows = db.list_journey_rows(conn, hours=hours)
        def cell(v: Any) -> str:
            return '"' + str(v or "").replace('"', '""') + '"'

        lines = ["ts,session_id,device_id,user_login,action,item_key,source,owner"]
        for r in rows:
            lines.append(",".join(cell(r.get(k)) for k in (
                "ts", "session_id", "device_id", "user_login",
                "action", "item_key", "source", "owner",
            )))
        return Response(
            "\n".join(lines) + "\n",
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=skillfeeder-journeys.csv"},
        )

    @app.post("/api/op/posts/{post_id}")
    def api_op_moderate(
        post_id: int, request: Request, body: ModerateBody,
    ) -> dict[str, Any]:
        uid, _ = _op_user(request)
        try:
            with db.db_session(settings.db_path) as conn:
                post = db.moderate_post(
                    conn, post_id, action=body.action, actor_id=uid, note=body.note,
                )
                if body.ban_author or body.action == "ban":
                    db.set_user_banned(conn, int(post["author_id"]), True)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        # 审核通过后自动推送到飞书底表（失败不阻塞审核流程）
        if body.action == "approve":
            try:
                _push_ugc_to_bitable(post)
            except Exception:  # noqa: BLE001
                pass  # 推送失败不影响审核结果，下次 export 会补
        return {"ok": True, "post": post}

    @app.get("/api/posts/me")
    def api_my_posts(request: Request) -> dict[str, Any]:
        uid = auth.require_user_id(request, settings)
        with db.db_session(settings.db_path) as conn:
            posts = db.list_user_posts(conn, uid)
        return {"posts": posts}

    @app.post("/api/posts/{post_id}/react")
    def api_react(post_id: int, request: Request, body: ReactBody) -> dict[str, Any]:
        uid = auth.require_user_id(request, settings)
        with db.db_session(settings.db_path) as conn:
            post = db.get_post(conn, post_id)
            if not post or post.get("status") not in ("published", "approved"):
                raise HTTPException(404, "post not found")
            db.set_reaction(conn, user_id=uid, post_id=post_id, kind=body.kind, on=body.on)
        return {"ok": True}

    return app


def __getattr__(name: str):  # PEP 562
    """`uvicorn server.app:app` 走 getattr，所以延迟构建即可。

    不能在模块顶层写 `app = create_app()`：create_app 现在是 fail-closed 的，
    缺 SKILLFEED_SESSION_SECRET 会抛异常，那样连 `import server.app` 都会炸，
    测试和工具脚本全部连带失败。延迟到真正要跑服务时再检查。
    """
    if name == "app":
        # 启动提示只在这里打印：测试会调 create_app() 上百次，放在那里会刷几百行
        # 噪音，把 unittest 的失败摘要顶出屏幕（实际发生过）。走到这里才是真起服务。
        app = create_app()
        for note in get_settings().startup_notes():
            print(note)
        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
