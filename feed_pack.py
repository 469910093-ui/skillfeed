"""把扫描/门禁结果打成可刷的信息流 payload（瘦字段、补 soft skill）。"""

from __future__ import annotations

from typing import Any, Optional

import highlights as hl
import rank
import scene

# 嵌入 HTML 时保留的字段（控制体积）
KEEP_KEYS = (
    "id", "full_name", "name", "description", "url", "source", "kind",
    "language", "stars", "stars_today", "skill_path",
    "hg_section", "issue", "hellogithub_url",
    "scene", "scene_label", "scene_l2", "scene_l2_label",
    "rel_score", "rel_why", "personal_score", "personal_why", "rank_why",
    "from_corpus", "soft", "owner", "one_liner",
    "body_preview", "cover_url", "skill_url",
    "problem", "highlights",
)

BODY_PREVIEW_MAX = 700


def _owner(full_name: str) -> str:
    if "/" in (full_name or ""):
        return full_name.split("/", 1)[0]
    return full_name or ""


def cover_url_for(full_name: str) -> str:
    """GitHub 仓库社交预览图（真实封面，非纯色占位）。"""
    fn = (full_name or "").strip()
    if "/" not in fn:
        return ""
    return f"https://opengraph.githubassets.com/1/{fn}"


def skill_url_for(full_name: str, skill_path: str = "") -> str:
    fn = (full_name or "").strip()
    if "/" not in fn:
        return ""
    path = (skill_path or "SKILL.md").lstrip("/")
    return f"https://github.com/{fn}/blob/HEAD/{path}"


def _preview_lookup(rows: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for r in rows:
        fn = r.get("full_name") or ""
        bp = (r.get("body_preview") or "").strip()
        if fn and bp and fn not in out:
            out[fn] = bp
    return out


def normalize_item(item: dict, *, previews: Optional[dict[str, str]] = None) -> dict:
    """瘦身 + 补展示字段（封面图 / SKILL 正文预览）。"""
    out = dict(item)
    fn = out.get("full_name") or ""
    out["full_name"] = fn
    out["url"] = out.get("url") or (f"https://github.com/{fn}" if fn else "")
    out["name"] = (out.get("name") or (fn.split("/")[-1] if fn else "skill")).strip()
    desc = (out.get("description") or out.get("repo_description") or "").strip()
    out["description"] = desc[:400]
    out["one_liner"] = desc[:140] + ("…" if len(desc) > 140 else "")
    out["owner"] = _owner(fn)
    bp = (out.get("body_preview") or "").strip()
    if not bp and previews and fn in previews:
        bp = previews[fn]
    if bp:
        out["body_preview"] = bp[:BODY_PREVIEW_MAX] + ("…" if len(bp) > BODY_PREVIEW_MAX else "")
    tips = hl.extract_highlights(bp or "", desc)
    out["problem"] = tips.get("problem") or out["one_liner"]
    out["highlights"] = list(tips.get("highlights") or [])
    out["cover_url"] = out.get("cover_url") or cover_url_for(fn)
    out["skill_url"] = out.get("skill_url") or skill_url_for(fn, out.get("skill_path") or "")
    if out.get("stars") is None:
        out["stars"] = None
    else:
        try:
            out["stars"] = int(out["stars"])
        except (TypeError, ValueError):
            out["stars"] = None
    kind = out.get("kind") or ""
    if not kind:
        if out.get("skill_path") or (out.get("hg_section") or "") == "Skills":
            kind = "skill"
        elif (out.get("hg_section") or "") == "人工智能":
            kind = "ai"
        else:
            kind = "oss"
    out["kind"] = kind
    # 丢掉大字段
    slim = {k: out[k] for k in KEEP_KEYS if k in out and out[k] is not None}
    # 显式保留 None stars（前端显示 —）
    if "stars" in out:
        slim["stars"] = out["stars"]
    slim.setdefault("from_corpus", bool(out.get("from_corpus")))
    slim.setdefault("soft", bool(out.get("soft")))
    return slim


def soft_skills_from_corpus(
    corpus_rows: list[dict],
    *,
    exclude: set[str],
    limit: int = 40,
) -> list[dict]:
    """知识库里 HelloGitHub Skills / 已标 skill，未过本轮探测的也进信息流。"""
    out: list[dict] = []
    for c in corpus_rows:
        fn = c.get("full_name") or ""
        if not fn or fn in exclude:
            continue
        sec = c.get("hg_section") or ""
        kind = c.get("kind") or ""
        if sec != "Skills" and kind != "skill":
            continue
        row = dict(c)
        row["kind"] = "skill"
        row["from_corpus"] = True
        row["soft"] = True
        if not row.get("source") or row.get("source") == "corpus":
            row["source"] = "hellogithub" if sec == "Skills" else (row.get("source") or "corpus")
        if not row.get("scene"):
            row = scene.apply_scene(row)
        out.append(row)
        if len(out) >= limit:
            break
    return out


def pack_feed(
    *,
    passed: list[dict],
    corpus_rows: list[dict],
    meta: dict,
    gates_summary: dict,
    funnel: dict,
    affinity: Optional[dict] = None,
    intent: str = "",
    config: Optional[dict] = None,
    soft_limit: int = 40,
    skill_pool: Optional[list[dict]] = None,
) -> dict[str, Any]:
    """
    组装最终 feed.json：
    - items：本轮过门禁 skill + 知识库 soft Skills（可刷）
    - corpus：其余 backup（Explore / 无限滑补货）
    """
    aff = affinity or {}
    live = [scene.apply_scene(p) if not p.get("scene") else p for p in passed]
    live = rank.rerank(live, affinity=aff, intent=intent)
    live_names = {p.get("full_name") for p in live if p.get("full_name")}

    pool = list(skill_pool or []) + list(corpus_rows or [])
    soft = soft_skills_from_corpus(pool, exclude=live_names, limit=soft_limit)
    soft = rank.rerank(soft, affinity=aff, intent=intent)
    previews = _preview_lookup(pool + live + soft)

    items = [normalize_item(x, previews=previews) for x in (live + soft)]

    used = {x.get("full_name") for x in items}
    browse: list[dict] = []
    for c in corpus_rows:
        fn = c.get("full_name") or ""
        if fn in used:
            continue
        row = scene.apply_scene(c) if not c.get("scene") else dict(c)
        row["from_corpus"] = True
        browse.append(row)
    browse = rank.rerank(browse, affinity=aff, intent=intent)
    browse = [normalize_item(x, previews=previews) for x in browse]

    funnel = dict(funnel or {})
    funnel["soft_skills"] = len(soft)
    funnel["stream_items"] = len(items)
    funnel["corpus_backup"] = len(browse)

    return {
        "meta": meta,
        "config": config or {},
        "gates": gates_summary,
        "funnel": funnel,
        "scenes": scene.scene_chips(),
        "scenes_l2": scene.scene_l2_tree(),
        "affinity": {
            "events": aff.get("events", 0),
            "top_scenes": sorted(
                (aff.get("scene_boost") or {}).items(),
                key=lambda x: -x[1],
            )[:5],
        },
        "items": items,
        "corpus": browse,
        "rejected_counts": (gates_summary or {}).get("rejected", {}),
        "ui": {
            "style": "instagram",
            "cta": "open_github",
            "demo_auto": False,
            "variant": "full",
        },
    }
