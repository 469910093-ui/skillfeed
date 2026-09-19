"""运营通知：投稿进审后推一条，失败不影响投稿。"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from server import db
from server.config import Settings


def review_url(settings: Settings) -> str:
    return f"{settings.public_url.rstrip('/')}/op?tab=review"


def resolve_review_webhook(settings: Settings) -> str:
    if (settings.review_webhook or "").strip():
        return settings.review_webhook.strip()
    try:
        with db.db_session(settings.db_path) as conn:
            return (db.get_site_setting(conn, "review_webhook") or "").strip()
    except Exception:
        return ""


def pending_review_text(settings: Settings, post: dict[str, Any]) -> str:
    title = (post.get("title") or "").strip() or "(无标题)"
    author = (post.get("author_login") or "").strip() or "?"
    github = (post.get("github_url") or "").strip()
    lines = [
        "SkillFeeder 有新投稿待审",
        f"标题：{title}",
        f"作者：{author}",
    ]
    if github:
        lines.append(f"仓库：{github}")
    lines.append(f"审核：{review_url(settings)}")
    return "\n".join(lines)


def _payload(webhook: str, text: str) -> dict[str, Any]:
    host = (urlparse(webhook).hostname or "").lower()
    if host.endswith("feishu.cn") or host.endswith("larksuite.com"):
        return {"msg_type": "text", "content": {"text": text}}
    return {"text": text}


def notify_pending_review(settings: Settings, post: dict[str, Any]) -> bool:
    """投稿落库后叫运营。没配 webhook 或推送失败都返回 False，不抛给用户。"""
    webhook = resolve_review_webhook(settings)
    if not webhook:
        return False
    text = pending_review_text(settings, post)
    try:
        resp = httpx.post(webhook, json=_payload(webhook, text), timeout=8.0)
        resp.raise_for_status()
    except Exception:
        return False
    return True
