"""UGC 帖 → Feed 卡片字段；解析 SKILL.md / 打场景标。"""

from __future__ import annotations

import json
import re
from typing import Any
import scene
from feed_pack import cover_url_for


_GH_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    r"(?:/(?:tree|blob)/(?P<ref>[^/]+)/(?P<path>.*))?"
    r"/?(?:[?#].*)?$",
    re.I,
)


def parse_github_url(url: str) -> str:
    """返回 full_name 或空串。"""
    parsed = parse_github_ref(url)
    return f"{parsed[0]}/{parsed[1]}" if parsed else ""


def parse_github_ref(url: str) -> tuple[str, str, str] | None:
    """owner, repo, skill_path。只认 github.com。"""
    m = _GH_RE.match((url or "").strip())
    if not m:
        return None
    owner = m.group("owner").lower()
    repo = m.group("repo").removesuffix(".git").lower()
    raw = (m.group("path") or "").strip().strip("/")
    parts = [p for p in raw.split("/") if p and p != "."]
    if ".." in parts:
        return None
    if parts and parts[-1].lower() == "skill.md":
        skill_path = "/".join(parts)
    elif parts:
        skill_path = "/".join(parts) + "/SKILL.md"
    else:
        skill_path = "SKILL.md"
    return owner, repo, skill_path


def listing_public_id(owner: str, repo: str, skill_path: str) -> str:
    return f"ugc:{owner}/{repo}::{skill_path}"


def prepare_post_payload(
    *,
    title: str,
    github_url: str,
    description: str,
    body_md: str = "",
    author_login: str = "",
) -> dict[str, Any]:
    """创作者只交链接 + 标题 + 文案。body_md 即使传来也丢弃，不落库、不渲染。"""
    del body_md  # 旧客户端可能还传；明确不采用
    title = (title or "").strip()
    github_url = (github_url or "").strip()
    desc = (description or "").strip()
    if not github_url:
        raise ValueError("请贴 GitHub 仓库或 SKILL.md 所在目录")
    parsed = parse_github_ref(github_url)
    if not parsed:
        raise ValueError("GitHub 链接格式应为 https://github.com/owner/repo")
    owner, repo, skill_path = parsed
    if not title:
        raise ValueError("标题必填（最多 60 字）")
    if len(title) > 60:
        raise ValueError("标题最多 60 字")
    if len(desc) < 2:
        raise ValueError("文案必填，请写清这个 skill 做什么")
    if len(desc) > 280:
        raise ValueError("文案最多 280 字")

    full_name = f"{owner}/{repo}"
    github_url = f"https://github.com/{full_name}" + (
        "" if skill_path == "SKILL.md" else f"/tree/HEAD/{skill_path.rsplit('/', 1)[0]}"
    )
    public_id = listing_public_id(owner, repo, skill_path)
    owner_ok = bool(author_login) and author_login.lower() == owner
    tagged = scene.apply_scene({
        "name": title,
        "description": desc,
        "body_preview": desc,
        "full_name": full_name,
        "keywords": "",
    })
    return {
        "name": title,
        "title": title,
        "description": desc,
        "body_md": "",
        "body_preview": desc,
        "problem": desc[:140],
        "highlights": [],
        "github_url": github_url,
        "full_name": full_name,
        "skill_path": skill_path,
        "public_id": public_id,
        "url": github_url,
        "source": "ugc",
        "kind": "skill",
        "cover_url": cover_url_for(full_name),
        "status": "pending",
        "featured": 0,
        "github_meta": {
            "owner_ok": owner_ok,
            "has_skill_md": None,
        },
        "scene": tagged.get("scene") or "other",
        "scene_label": tagged.get("scene_label") or "其他",
        "scene_l2": tagged.get("scene_l2") or "",
        "scene_l2_label": tagged.get("scene_l2_label") or "",
    }


def post_to_feed_item(post: dict[str, Any]) -> dict[str, Any]:
    fn = post.get("full_name") or ""
    url = post.get("github_url") or (f"https://github.com/{fn}" if fn else "")
    desc = post.get("description") or ""
    skill_path = post.get("skill_path") or "SKILL.md"
    return {
        "id": post.get("public_id") or f"ugc:{fn}::{skill_path}",
        "ugc_id": post["id"],
        "full_name": fn or f"ugc/{post['id']}",
        "name": post.get("title") or "skill",
        "description": desc,
        "one_liner": desc[:140],
        "body_preview": desc,
        "problem": desc[:140],
        "highlights": [],
        "skill_path": skill_path,
        "url": url,
        "skill_url": url,
        "cover_url": post.get("cover_url") or cover_url_for(fn),
        "source": "ugc",
        "kind": "skill",
        "scene": post.get("scene") or "other",
        "scene_label": post.get("scene_label") or "其他",
        "scene_l2": post.get("scene_l2") or "",
        "scene_l2_label": post.get("scene_l2_label") or "",
        "stars": None,
        "author_login": post.get("author_login") or "",
        "author_avatar": post.get("author_avatar") or "",
        "soft": False,
        "from_corpus": False,
        "ugc": True,
    }


def load_official_items_from_file(path: Any) -> list[dict]:
    """从服务器本地的 publish-site 产物读官方流。

    国内主站的默认取法：同源、零出网，也就不存在「跨境拉 feed.json 超时导致
    首屏空白」。产物由 `skillfeed.py publish-site` 生成，本函数只读。
    """
    from pathlib import Path
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    return list(data.get("items") or [])


async def load_official_items(feed_url: str) -> list[dict]:
    if not feed_url:
        return []
    try:
        import httpx
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(feed_url)
            r.raise_for_status()
            data = r.json()
    except Exception:  # noqa: BLE001
        return []
    items = list(data.get("items") or [])
    # corpus 作补货，但官方流优先 items
    return items
