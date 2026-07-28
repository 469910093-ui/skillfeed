"""skill-feed 云端 API：GitHub 登录 + UGC 发布 + 混排 Feed。"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from server import auth, db, ugc
from server.config import Settings, get_settings

ROOT = Path(__file__).resolve().parent
TEMPLATES = ROOT / "templates"


class PostCreate(BaseModel):
    title: str = ""
    body_md: str = ""
    github_url: str = ""
    description: str = ""


class ReactBody(BaseModel):
    kind: str = Field(pattern="^(like|save|bad)$")
    on: bool = True


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or get_settings()
    db.init_db(settings.db_path)

    app = FastAPI(
        title="skill-feed API",
        version="0.2.0",
        description="GitHub 登录 · UGC 发布 skill · 混排 Feed（不代装）",
    )
    app.state.settings = settings

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins or ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    static_dir = ROOT / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "ok": True,
            "oauth": settings.oauth_configured,
            "dev_auth": settings.dev_auth,
            "official_feed": bool(settings.official_feed_url),
        }

    @app.get("/", response_class=HTMLResponse)
    def home() -> HTMLResponse:
        html = (TEMPLATES / "home.html").read_text(encoding="utf-8")
        return HTMLResponse(html)

    @app.get("/publish", response_class=HTMLResponse)
    def publish_page(request: Request) -> HTMLResponse:
        uid = auth.session_user_id(request, settings)
        html = (TEMPLATES / "publish.html").read_text(encoding="utf-8")
        html = html.replace("{{logged_in}}", "1" if uid else "0")
        html = html.replace("{{public_url}}", settings.public_url)
        return HTMLResponse(html)

    # —— Auth ——
    @app.get("/auth/github")
    def auth_github(response: Response) -> RedirectResponse:
        if not settings.oauth_configured:
            if settings.dev_auth:
                return RedirectResponse("/auth/dev-login", status_code=302)
            raise HTTPException(
                status_code=503,
                detail="未配置 GitHub OAuth（SKILLFEED_GITHUB_CLIENT_ID/SECRET）。本地可设 SKILLFEED_DEV_AUTH=1",
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
        if not settings.dev_auth:
            raise HTTPException(404, "dev auth disabled")
        with db.db_session(settings.db_path) as conn:
            user = db.upsert_user(
                conn,
                github_id=1,
                login=login[:39] or "dev-user",
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
    ) -> dict[str, Any]:
        ugc_items: list[dict] = []
        with db.db_session(settings.db_path) as conn:
            posts = db.list_published_posts(conn, limit=limit, offset=offset if source == "ugc" else 0)
            ugc_items = [ugc.post_to_feed_item(p) for p in posts]

        official: list[dict] = []
        if source in ("all", "official"):
            official = await ugc.load_official_items(settings.official_feed_url)

        if source == "ugc":
            items = ugc_items
        elif source == "official":
            items = official[:limit]
        else:
            # UGC 置顶，再接官方发现流（去重 full_name）
            seen = {i.get("full_name") for i in ugc_items}
            merged = list(ugc_items)
            for it in official:
                fn = it.get("full_name")
                if fn and fn in seen:
                    continue
                if fn:
                    seen.add(fn)
                merged.append(it)
            items = merged[offset: offset + limit]

        return {
            "items": items,
            "ugc_count": len(ugc_items) if source != "official" else 0,
            "official_count": len(official),
            "generated_mode": "api-merge",
            "me": None,
        }

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


app = create_app()
