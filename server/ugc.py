"""UGC 帖 → Feed 卡片字段；解析 SKILL.md / 打场景标。"""

from __future__ import annotations

import re
from typing import Any
import highlights as hl
import scene
import skill_detect
from feed_pack import cover_url_for


_GH_RE = re.compile(
    r"^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)(?:/|$)",
    re.I,
)


def parse_github_url(url: str) -> str:
    """返回 full_name 或空串。"""
    m = _GH_RE.match((url or "").strip())
    if not m:
        return ""
    return f"{m.group(1)}/{m.group(2).removesuffix('.git')}"


def prepare_post_payload(
    *,
    title: str,
    body_md: str,
    github_url: str = "",
    description: str = "",
) -> dict[str, Any]:
    title = (title or "").strip()
    body_md = (body_md or "").strip()
    github_url = (github_url or "").strip()
    if not body_md and not github_url:
        raise ValueError("需要 SKILL.md 正文或 GitHub 仓库链接")
    if len(body_md) > 20000:
        raise ValueError("SKILL.md 正文过长（最多 20000 字）")

    meta = skill_detect.parse_skill_md(body_md) if body_md else {
        "name": "", "description": "", "keywords": "", "body_preview": "", "frontmatter": {},
    }
    name = title or meta.get("name") or ""
    desc = (description or meta.get("description") or "").strip()
    if not name:
        # 从 github path 兜底
        fn = parse_github_url(github_url)
        name = fn.split("/")[-1] if fn else "untitled-skill"
    if not desc:
        desc = (body_md.splitlines()[0] if body_md else name)[:200]
    if len(desc) < 10:
        raise ValueError("描述太短，请写清这个 skill 做什么（至少约 10 字）")

    full_name = parse_github_url(github_url)
    if github_url and not full_name:
        raise ValueError("GitHub 链接格式应为 https://github.com/owner/repo")
    if github_url and not github_url.startswith("http"):
        github_url = f"https://github.com/{full_name}"

    body_preview = (meta.get("body_preview") or body_md or desc)[:700]
    tips = hl.extract_highlights(body_preview, desc)
    item = {
        "name": name,
        "title": name,
        "description": desc[:400],
        "body_md": body_md or f"# {name}\n\n{desc}\n",
        "body_preview": body_preview,
        "problem": tips.get("problem") or desc[:140],
        "highlights": tips.get("highlights") or [],
        "github_url": github_url or (f"https://github.com/{full_name}" if full_name else ""),
        "full_name": full_name,
        "url": github_url or (f"https://github.com/{full_name}" if full_name else ""),
        "source": "ugc",
        "kind": "skill",
        "cover_url": cover_url_for(full_name) if full_name else "",
    }
    tagged = scene.apply_scene({
        "name": item["name"],
        "description": item["description"],
        "body_preview": item["body_preview"],
        "full_name": full_name,
        "keywords": meta.get("keywords") or "",
    })
    item["scene"] = tagged.get("scene") or "other"
    item["scene_label"] = tagged.get("scene_label") or "其他"
    item["scene_l2"] = tagged.get("scene_l2") or ""
    item["scene_l2_label"] = tagged.get("scene_l2_label") or ""
    return item


def post_to_feed_item(post: dict[str, Any]) -> dict[str, Any]:
    fn = post.get("full_name") or ""
    url = post.get("github_url") or (f"https://github.com/{fn}" if fn else "")
    body_preview = (post.get("body_md") or "")[:700]
    tips = hl.extract_highlights(body_preview, post.get("description") or "")
    return {
        "id": f"ugc:{post['id']}",
        "ugc_id": post["id"],
        "full_name": fn or f"ugc/{post['id']}",
        "name": post.get("title") or "skill",
        "description": post.get("description") or "",
        "one_liner": (post.get("description") or "")[:140],
        "body_preview": body_preview,
        "problem": tips.get("problem") or (post.get("description") or "")[:140],
        "highlights": tips.get("highlights") or [],
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
