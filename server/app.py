"""skill-feed 云端 API：GitHub 登录 + UGC 发布 + 混排 Feed。"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import ranking
from server import auth, db, metrics, ranking_service, ugc
from server.config import Settings, get_settings
from server.ratelimit import EventLimiter

ROOT = Path(__file__).resolve().parent
TEMPLATES = ROOT / "templates"

MAX_EVENTS_PER_REQUEST = 200


class PostCreate(BaseModel):
    title: str = ""
    body_md: str = ""
    github_url: str = ""
    description: str = ""


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
            "dev_auth": settings.dev_auth,
            "official_feed": bool(settings.official_feed_url),
            "events_total": int(row["n"] or 0),
            "last_event_age_s": round(age, 1) if age is not None else None,
            "ingest_stale": bool(age is not None and age > stale_after),
        }

    @app.get("/", response_class=HTMLResponse)
    def home() -> HTMLResponse:
        nonce = secrets.token_urlsafe(16)
        html = (TEMPLATES / "home.html").read_text(encoding="utf-8")
        return html_response(html.replace("{{csp_nonce}}", nonce), nonce)

    @app.get("/publish", response_class=HTMLResponse)
    def publish_page(request: Request) -> HTMLResponse:
        uid = auth.session_user_id(request, settings)
        nonce = secrets.token_urlsafe(16)
        html = (TEMPLATES / "publish.html").read_text(encoding="utf-8")
        html = html.replace("{{logged_in}}", "1" if uid else "0")
        html = html.replace("{{public_url}}", settings.public_url)
        return html_response(html.replace("{{csp_nonce}}", nonce), nonce)

    # —— Auth ——
    @app.get("/auth/github")
    def auth_github(response: Response) -> RedirectResponse:
        if not settings.oauth_configured:
            # 这里过去会在 dev_auth 时 302 到 /auth/dev-login（无凭据发 30 天会话）。
            # 那是个静默降级：接微信登录的改造期漏配一个环境变量，站点就变成
            # 「点一下就登进去」。现在一律报错，降级只能由显式访问 dev-login 触发。
            raise HTTPException(
                status_code=503,
                detail="未配置 GitHub OAuth（SKILLFEED_GITHUB_CLIENT_ID/SECRET）。",
            )
        state = secrets.token_urlsafe(16)
        resp = RedirectResponse(auth.github_authorize_url(settings, state), status_code=302)
        resp.set_cookie("skillfeed_oauth_state", state, httponly=True, max_age=600, samesite="lax", path="/")
        return resp

    @app.get("/auth/callback")
    async def auth_callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
        if not code:
            raise HTTPException(400, "missing code")
        expect = request.cookies.get("skillfeed_oauth_state") or ""
        if not state or state != expect:
            raise HTTPException(400, "bad oauth state")
        gh = await auth.exchange_github_code(settings, code)
        with db.db_session(settings.db_path) as conn:
            user = db.upsert_user(
                conn,
                github_id=int(gh["id"]),
                login=gh.get("login") or "",
                avatar_url=gh.get("avatar_url") or "",
                name=gh.get("name") or "",
            )
        resp = RedirectResponse("/publish", status_code=302)
        auth.set_session_cookie(resp, settings, int(user["id"]), user["login"])
        resp.delete_cookie("skillfeed_oauth_state", path="/")
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
        uid = auth.session_user_id(request, settings)
        if uid is None:
            return {"user": None, "oauth": settings.oauth_configured, "dev_auth": settings.dev_auth}
        with db.db_session(settings.db_path) as conn:
            user = db.get_user(conn, uid)
        return {
            "user": db.user_public(user) if user else None,
            "oauth": settings.oauth_configured,
            "dev_auth": settings.dev_auth,
        }

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
    ) -> dict[str, Any]:
        cfg = app.state.ranking_config
        device_id = _device_id(request, device_id)
        ugc_items: list[dict] = []
        with db.db_session(settings.db_path) as conn:
            posts = db.list_published_posts(conn, limit=200, offset=0)
            ugc_items = [ugc.post_to_feed_item(p) for p in posts]

        official: list[dict] = []
        if source in ("all", "official"):
            official = await ugc.load_official_items(settings.official_feed_url)

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

        total = len(ranked)
        page = ranked[offset: offset + limit]
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
    @app.post("/api/posts")
    async def api_create_post(request: Request, body: PostCreate) -> dict[str, Any]:
        uid = auth.require_user_id(request, settings)
        try:
            prepared = ugc.prepare_post_payload(
                title=body.title,
                body_md=body.body_md,
                github_url=body.github_url,
                description=body.description,
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        with db.db_session(settings.db_path) as conn:
            post = db.create_post(conn, uid, prepared)
        return {"ok": True, "post": post, "feed_item": ugc.post_to_feed_item(post)}

    @app.post("/api/posts/form")
    async def api_create_post_form(
        request: Request,
        title: str = Form(""),
        body_md: str = Form(""),
        github_url: str = Form(""),
        description: str = Form(""),
    ) -> RedirectResponse:
        uid = auth.require_user_id(request, settings)
        try:
            prepared = ugc.prepare_post_payload(
                title=title, body_md=body_md, github_url=github_url, description=description,
            )
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        with db.db_session(settings.db_path) as conn:
            db.create_post(conn, uid, prepared)
        return RedirectResponse("/publish?ok=1", status_code=303)

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
            if not post or post.get("status") != "published":
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
