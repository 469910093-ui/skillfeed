"""把扫描/门禁结果打成可刷的信息流 payload（瘦字段、补 soft skill）。"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import highlights as hl
import impressions
import rank
import ranking
import scene
import star_history

# 嵌入 HTML 时保留的字段（控制体积）
# 注意：normalize_item 按这个白名单裁字段，没列进来的新字段会被静默丢弃
KEEP_KEYS = (
    "id", "full_name", "name", "description", "url", "source", "kind",
    "language", "stars", "stars_today", "skill_path",
    "hg_section", "issue", "hellogithub_url",
    "scene", "scene_label", "scene_l2", "scene_l2_label",
    "rel_score", "rel_why", "personal_score", "personal_why", "rank_why",
    "global_score", "global_why", "first_seen_at", "is_new", "star_velocity",
    "repo_items",
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
    out["id"] = out.get("id") or item_key(out)
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


def item_key(it: dict) -> str:
    """同一 GitHub 仓可有多条子 skill，用 full_name::skill_path 区分。"""
    if it.get("id"):
        return str(it["id"])
    fn = it.get("full_name") or ""
    sp = (it.get("skill_path") or "SKILL.md").lstrip("/")
    return f"{fn}::{sp}" if fn else sp


def soft_skills_from_corpus(
    corpus_rows: list[dict],
    *,
    exclude: set[str],
    limit: int = 40,
) -> list[dict]:
    """知识库里 HelloGitHub Skills / 已标 skill，未过本轮探测的也进信息流。

    调用方喂进来的池子是 skill_pool + corpus_rows 拼的，两段都从同一份 corpus
    读，同一条 skill 会出现两次。所以自己产出的键也要挡回去——只看入参 exclude
    的话，线上会出现 id 一模一样的两张卡（实测 4 条 hellogithub 条目中招）。
    """
    out: list[dict] = []
    seen: set[str] = set()
    for c in corpus_rows:
        fn = c.get("full_name") or ""
        key = item_key(c)
        # exclude 兼容旧逻辑（只含 full_name）与新逻辑（含 id）
        if not fn or key in exclude or fn in exclude or key in seen:
            continue
        seen.add(key)
        sec = c.get("hg_section") or ""
        kind = c.get("kind") or ""
        if sec != "Skills" and kind != "skill":
            continue
        row = dict(c)
        row["kind"] = "skill"
        row["from_corpus"] = True
        row["soft"] = True
        row.setdefault("id", key)
        if not row.get("source") or row.get("source") == "corpus":
            row["source"] = "hellogithub" if sec == "Skills" else (row.get("source") or "corpus")
        if not row.get("scene"):
            row = scene.apply_scene(row)
        out.append(row)
        if len(out) >= limit:
            break
    return out


def apply_global_scores(
    rows: list[dict],
    *,
    data_dir: Optional[Path] = None,
    config: Optional[dict] = None,
    now: Optional[datetime] = None,
) -> list[dict]:
    """给条目打全局质量分（CTR + star 增速 + 存量 + 新鲜度 + 完整度）。

    star 增速要跨天对比才算得出来，所以这里顺带落一次快照；本机版的 CTR 从
    feedback.jsonl 聚合，线上版由 server 侧用 SQLite 的统计覆盖重算。
    """
    if not rows:
        return rows
    cfg = ranking.resolve_config(config)
    now = now or datetime.now(timezone.utc)
    home = star_history.data_home(data_dir)
    snapshot = star_history.observe(rows, data_dir=home, now=now)
    first_seen = star_history.first_seen_map(rows, data_dir=home, now=now)
    try:
        # 三个来源并集：本机 jsonl + 同机 server.db + 线上导出的 item_stats.json。
        # 静态形态（GitHub Pages）没有服务端，运行期个性化做不了，但「站内热度」
        # 是全站聚合量，可以在这里烧进 feed.json —— 这是规则 1 后半句在静态站
        # 唯一的落地位置
        stats = impressions.load_stats(home, config=cfg)
    except OSError:
        stats = {}
    gstats = ranking.build_global_stats(stats, rows)
    ranking.annotate_repo_share(rows, config=cfg)

    for row in rows:
        fn = row.get("full_name") or ""
        row.setdefault("first_seen_at", first_seen.get(fn) or now.isoformat())
        st = stats.get(row.get("id") or fn)
        score, why = ranking.global_quality(
            row, stats=st, gstats=gstats, star_snapshot=snapshot, config=cfg, now=now,
        )
        gain, conf = ranking.velocity_parts(row, snapshot)
        row["global_score"] = score
        row["global_why"] = why
        row["is_new"] = ranking.is_new_item(row, st, cfg, now)
        row["star_velocity"] = round(gain, 3) if conf > 0 else None
    return rows


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
    data_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """
    组装最终 feed.json：
    - items：本轮过门禁 skill + 知识库 soft Skills（可刷）
    - corpus：其余 backup（Explore / 无限滑补货）
    """
    aff = affinity or {}
    # 始终重打场景：规则升级后（如产品设计路径优先）需覆盖旧标签
    live = [scene.apply_scene(dict(p)) for p in passed]
    live = rank.rerank(live, affinity=aff, intent=intent)
    live_keys = {item_key(p) for p in live}
    live_names = {p.get("full_name") for p in live if p.get("full_name")}

    pool = list(skill_pool or []) + list(corpus_rows or [])
    soft = soft_skills_from_corpus(pool, exclude=live_keys | live_names, limit=soft_limit)
    soft = rank.rerank(soft, affinity=aff, intent=intent)
    previews = _preview_lookup(pool + live + soft)

    stream = apply_global_scores(live + soft, data_dir=data_dir, config=config)
    items = [normalize_item(x, previews=previews) for x in stream]

    used = {item_key(x) for x in items} | {x.get("full_name") for x in items if x.get("full_name")}
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
        # 这里只放**会被读**的字段。曾经有过一个 "style" 键，值是某个第三方 App 的
        # 名字，全库没有任何代码读它，但它会随 feed.json 发布到公开站点——等于在生产
        # 产物里留一句机器可读的「我们是谁的仿版」。删掉了，别再加回来；
        # tests/test_publish_site.py::TestPublishedUiBlock 会拦。
        "ui": {
            "cta": "open_github",
            "demo_auto": False,
            "variant": "full",
        },
    }
