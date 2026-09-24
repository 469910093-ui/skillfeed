"""已购技能包交付：手册、技能排序、应用介绍、知识库。

正文只在购买后由 API 下发，不写进公开页。名单来自策展表里已点名的技能。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1] / "docs" / "packs" / "delivery"
_SHELF = Path(__file__).resolve().parents[1] / "docs" / "packs" / "shelf_catalog.json"
_BAD = ("待补采", "未点名", "未写", "未拆", "逐个名未点", "笔记未")


def shelf_status(pack_id: str) -> str:
    """返回货架 status：shelf / soon / ''（未知）。"""
    safe = (pack_id or "").strip()
    if not safe or not _SHELF.is_file():
        return ""
    try:
        data = json.loads(_SHELF.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    for raw in data.get("packs") or []:
        if isinstance(raw, dict) and str(raw.get("id") or "").strip() == safe:
            return str(raw.get("status") or "").strip()
    return ""


def is_sellable_pack(pack_id: str) -> bool:
    return shelf_status(pack_id) == "shelf"


def _clean_url(url: str) -> str:
    text = (url or "").strip()
    if text.startswith("https://") or text.startswith("http://"):
        return text.split("?", 1)[0].split("#", 1)[0]
    return ""


def load_delivery(pack_id: str) -> Optional[dict[str, Any]]:
    """读一份交付。没有材料的包返回 None，调用方不要编一份空手册。"""
    safe = (pack_id or "").strip()
    if not safe or "/" in safe or ".." in safe or not safe.replace("-", "").isalnum():
        return None
    path = ROOT / f"{safe}.json"
    if not path.is_file():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    skills = []
    for row in raw.get("skills") or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if not name or any(flag in name for flag in _BAD):
            continue
        skills.append({
            "order": int(row.get("order") or len(skills) + 1),
            "name": name,
            "step": str(row.get("step") or "").strip(),
            "intro": str(row.get("intro") or "").strip(),
        })
    apps = [{"name": s["name"], "intro": s["intro"]} for s in skills]
    kb = []
    for row in raw.get("kb") or []:
        if not isinstance(row, dict):
            continue
        url = _clean_url(str(row.get("url") or ""))
        if not url:
            continue
        topics = [str(t).strip() for t in (row.get("topics") or []) if str(t).strip()]
        kb.append({
            "source": str(row.get("source") or "").strip(),
            "url": url,
            "topics": topics,
        })
    title = str(raw.get("title") or safe).strip()
    md = str(raw.get("md") or "").strip()
    if not skills and not md:
        return None
    return {
        "id": safe,
        "title": title,
        "md": md,
        "skills": skills,
        "apps": apps,
        "kb": kb,
    }
