"""GitHub OAuth + HMAC 签名 Cookie 会话。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request, Response

from server.config import Settings

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_USER = "https://api.github.com/user"


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def sign_session(secret: str, payload: dict[str, Any], *, max_age: int) -> str:
    body = dict(payload)
    body["exp"] = int(time.time()) + max_age
    raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
    return f"{_b64e(raw)}.{_b64e(sig)}"


def verify_session(secret: str, token: str) -> Optional[dict[str, Any]]:
    try:
        raw_b64, sig_b64 = token.split(".", 1)
        raw = _b64d(raw_b64)
        sig = _b64d(sig_b64)
        expect = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expect):
            return None
        data = json.loads(raw.decode("utf-8"))
        if int(data.get("exp") or 0) < int(time.time()):
            return None
        return data
    except Exception:  # noqa: BLE001
        return None


def set_session_cookie(resp: Response, settings: Settings, user_id: int, login: str) -> None:
    token = sign_session(
        settings.session_secret,
        {"uid": user_id, "login": login},
        max_age=settings.cookie_max_age,
    )
    resp.set_cookie(
        settings.cookie_name,
        token,
        max_age=settings.cookie_max_age,
        httponly=True,
        samesite="lax",
        secure=settings.public_url.startswith("https://"),
        path="/",
    )


def clear_session_cookie(resp: Response, settings: Settings) -> None:
    resp.delete_cookie(settings.cookie_name, path="/")


def session_user_id(request: Request, settings: Settings) -> Optional[int]:
    token = request.cookies.get(settings.cookie_name) or ""
    if not token:
        return None
    data = verify_session(settings.session_secret, token)
    if not data:
        return None
    try:
        return int(data["uid"])
    except (KeyError, TypeError, ValueError):
        return None


def require_user_id(request: Request, settings: Settings) -> int:
    uid = session_user_id(request, settings)
    if uid is None:
        raise HTTPException(status_code=401, detail="login required")
    return uid


def github_authorize_url(settings: Settings, state: str) -> str:
    q = urlencode({
        "client_id": settings.github_client_id,
        "redirect_uri": f"{settings.public_url}/auth/callback",
        "scope": "read:user",
        "state": state,
    })
    return f"{GITHUB_AUTHORIZE}?{q}"


async def exchange_github_code(settings: Settings, code: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20) as client:
        token_resp = await client.post(
            GITHUB_TOKEN,
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": f"{settings.public_url}/auth/callback",
            },
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        access = token_data.get("access_token")
        if not access:
            raise HTTPException(status_code=400, detail=token_data.get("error") or "oauth failed")
        user_resp = await client.get(
            GITHUB_USER,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {access}",
                "User-Agent": "skill-feed-api",
            },
        )
        user_resp.raise_for_status()
        return user_resp.json()
