#!/usr/bin/env python3
"""skill-feed: 多源发现 → 门禁 → 无限下滑 Feed → 打开 GitHub（不代装）。

与 skill-picker 拆产品线：本工具负责联网发现与离线知识库；
skill-picker 继续只做 100% 本地扫描/匹配。

用法:
  python skillfeed.py refresh [--since daily|weekly] [--force] [--intent TEXT]
  python skillfeed.py build [--intent TEXT]   # 用已有 feed/corpus 重生信息流 HTML
  python skillfeed.py i18n [--force] [--limit N] [--model NAME]  # 只补中英双语人话字段
  python skillfeed.py bitable init|pull|push|sync|dedupe         # 译稿库（飞书多维表格）
  python skillfeed.py corpus [--max-issues N]
  python skillfeed.py xhs-crawl [--keyword TEXT] [--max N]  # 媒讯助手/Chrome 采小红书
  python skillfeed.py publish-site [--out DIR]  # 导出静态站（GitHub Pages）
  python skillfeed.py api [--host HOST] [--port N]  # 云端 API：登录 + UGC
  python skillfeed.py serve [--port N]
  python skillfeed.py check
  python skillfeed.py feedback

环境变量:
  SKILLFEED_HOME     数据目录（默认 ~/.skill-feed；CI 可设为仓库内路径）
  DASHSCOPE_API_KEY  阿里云百炼 key，用于生成中英双语卡片文案
  GITHUB_TOKEN       GitHub token；缺了 api.github.com 匿名会 403，monorepo 展不开
  详见 .env.example（OAuth / DB / 官方 feed URL）
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import bitable_store
import catalog_sources
import corpus
import feedback
import feed_dashboard
import feed_pack
import gates
import github_search
import hellogithub
import i18n
import rank
import scene
import skill_detect
import trending
import xiaohongshu

HOME = Path.home()
DEFAULTS_PATH = Path(__file__).resolve().parent / "config_defaults.json"


def data_dir() -> Path:
    """数据根目录。CI/网站构建用环境变量 SKILLFEED_HOME 覆盖。"""
    env = (os.environ.get("SKILLFEED_HOME") or "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return (HOME / ".skill-feed").resolve()


DATA_DIR = data_dir()
FEED_JSON = DATA_DIR / "feed.json"
FEED_HTML = DATA_DIR / "feed.html"
FEED_HTML_LITE = DATA_DIR / "feed.lite.html"
CONFIG_JSON = DATA_DIR / "config.json"


def refresh_paths() -> None:
    """SKILLFEED_HOME 在进程内被设置后，同步模块级路径。"""
    global DATA_DIR, FEED_JSON, FEED_HTML, FEED_HTML_LITE, CONFIG_JSON
    DATA_DIR = data_dir()
    FEED_JSON = DATA_DIR / "feed.json"
    FEED_HTML = DATA_DIR / "feed.html"
    FEED_HTML_LITE = DATA_DIR / "feed.lite.html"
    CONFIG_JSON = DATA_DIR / "config.json"


def write_local_feed_pages(feed: dict) -> None:
    """本机：full 独立站页 + lite（给 skill-picker 嵌入）。"""
    feed_dashboard.write_feed_variants(
        feed, full_path=FEED_HTML, lite_path=FEED_HTML_LITE,
    )


def run_i18n(feed: dict, cfg: dict, *, force: bool = False) -> None:
    """给入流条目补中英双语人话字段。缺 key 或失败都只降级，不中断构建。"""
    if not cfg.get("i18n_enabled", True):
        return
    key = str(cfg.get("dashscope_api_key") or "").strip() or os.environ.get(
        "DASHSCOPE_API_KEY", ""
    )
    stats = i18n.enrich_feed(
        DATA_DIR,
        feed,
        api_key=key,
        model=str(cfg.get("i18n_model") or i18n.DEFAULT_MODEL),
        base_url=str(cfg.get("i18n_base_url") or i18n.DEFAULT_BASE_URL),
        workers=int(cfg.get("i18n_workers") or i18n.DEFAULT_WORKERS),
        force=force,
        limit=int(cfg.get("i18n_limit") or 0),
    )
    print(
        "[i18n] "
        f"total={stats['total']} cached={stats['cached']} "
        f"locked={stats.get('locked', 0)} "
        f"translated={stats['translated']} failed={stats['failed']} "
        f"skipped={stats['skipped']}"
    )
    if not key and stats["skipped"]:
        print("[i18n] WARN 未设置 DASHSCOPE_API_KEY，未命中缓存的条目保持原文")


def retag_scenes(feed: dict) -> None:
    """i18n 之后重跑行业分类。

    pack_feed 里第一次分类只看得到英文 SKILL.md 原文，噪音大；等 i18n 把中文
    一句话写进条目后再判一次，判定质量明显更好。apply_scene 是幂等的。
    """
    items = feed.get("items") or []
    moved = 0
    for i, it in enumerate(items):
        before = it.get("scene") or ""
        items[i] = scene.apply_scene(it)
        if items[i].get("scene") != before:
            moved += 1
    if moved:
        print(f"[scene] i18n 后重判，{moved}/{len(items)} 条改了一级行业")
TOOL_FILES = [
    "skillfeed.py",
    "trending.py",
    "skill_detect.py",
    "gates.py",
    "rank.py",
    "feed_dashboard.py",
    "hellogithub.py",
    "github_search.py",
    "catalog_sources.py",
    "xiaohongshu.py",
    "corpus.py",
    "feed_pack.py",
    "highlights.py",
    "i18n.py",
    "bitable_store.py",
    "scene.py",
    "feedback.py",
    "config_defaults.json",
]


def load_config() -> dict:
    defaults = json.loads(DEFAULTS_PATH.read_text(encoding="utf-8"))
    if CONFIG_JSON.exists():
        try:
            user = json.loads(CONFIG_JSON.read_text(encoding="utf-8"))
            if isinstance(user, dict):
                defaults.update(user)
        except (json.JSONDecodeError, OSError):
            pass
    return defaults


def ensure_data_dir(cfg: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_JSON.exists():
        CONFIG_JSON.write_text(
            json.dumps({
                "min_stars": cfg["min_stars"],
                "min_rel": cfg["min_rel"],
                "since": cfg["since"],
                "ttl_hours": cfg["ttl_hours"],
                "gate_profile": cfg.get("gate_profile", "standard"),
                "interest_from": cfg["interest_from"],
                "hellogithub_repo": cfg.get("hellogithub_repo", "~/.hellogithub/HelloGitHub"),
                "hg_max_issues": cfg.get("hg_max_issues", 12),
            }, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


def self_copy() -> None:
    src_dir = Path(__file__).resolve().parent
    for name in TOOL_FILES:
        src = src_dir / name
        if src.exists():
            shutil.copy2(src, DATA_DIR / name)


def _item_key(it: dict) -> str:
    return it.get("id") or skill_detect.skill_item_id(
        it.get("full_name") or "", it.get("skill_path") or "",
    )


def _probe_candidates(
    rows: list[dict],
    ua: str,
    *,
    always_if_skills_section: bool = True,
    always_probe_all: bool = False,
    expand_limit: int = 6,
    token: str = "",
) -> tuple[list[dict], int]:
    enriched: list[dict] = []
    probed = 0
    for r in rows:
        always = always_probe_all or skill_detect.looks_like_skill_repo(
            r.get("description") or "", r.get("full_name") or "",
        )
        if always_if_skills_section and (r.get("hg_section") == "Skills" or r.get("kind") == "skill"):
            always = True
        if r.get("source") in ("github-search", "catalog", "xiaohongshu"):
            always = True
        probed += 1
        try:
            items = skill_detect.enrich_repo_multi(
                r, ua, always_probe=always, max_skills=expand_limit, token=token,
            )
        except Exception as e:  # noqa: BLE001
            print(f"[refresh] skip {r.get('full_name')}: {e}")
            continue
        for item in items:
            enriched.append(item)
            print(
                f"[refresh] skill hit: {item.get('full_name')} "
                f"[{item.get('name') or item.get('skill_path')}] <- {item.get('source')}"
            )
    return enriched, probed


def _pick_probe_rows(
    rows: list[dict],
    *,
    limit: int,
    force_names: Optional[set[str]] = None,
) -> list[dict]:
    """强制探测名单优先入队，其余按星数降序补齐。"""
    force = set(force_names or ())
    pinned: list[dict] = []
    rest: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        fn = (r.get("full_name") or "").strip()
        if not fn or fn in seen:
            continue
        seen.add(fn)
        if fn in force:
            pinned.append(r)
        else:
            rest.append(r)
    rest.sort(key=lambda x: int(x.get("stars") or 0), reverse=True)
    # 强制仓不占「普通配额」之外被截断：先全量 pinned，再补 rest
    out = pinned + rest
    # 若总量过大，至少保住 pinned；rest 用 limit 收束
    if len(out) <= max(limit, len(pinned)):
        return out
    return pinned + rest[: max(0, limit)]


def _resolve_github_token(cfg: dict) -> str:
    return (
        (cfg.get("github_token") or "").strip()
        or os.environ.get("GITHUB_TOKEN", "").strip()
        or os.environ.get("GH_TOKEN", "").strip()
    )


def cmd_xhs_crawl(argv: list[str]) -> int:
    """调用本机 Chrome（媒讯助手扩展）采集小红书 skill 相关笔记。"""
    refresh_paths()
    cfg = load_config()
    ensure_data_dir(cfg)
    script = Path(__file__).resolve().parent / "scripts" / "xhs_meixun_crawl.py"
    if not script.exists():
        print(f"missing {script}", file=sys.stderr)
        return 1
    # 复用同一解释器跑采集脚本
    import subprocess

    cmd = [sys.executable, str(script), "--data-dir", str(DATA_DIR), *argv]
    print(f"[xhs-crawl] {' '.join(cmd)}")
    return int(subprocess.call(cmd))


def cmd_corpus(argv: list[str]) -> int:
    refresh_paths()
    cfg = load_config()
    ensure_data_dir(cfg)
    max_issues = int(cfg.get("hg_max_issues_corpus", 0) or 0)  # 0=全刊
    i = 0
    while i < len(argv):
        if argv[i] == "--max-issues" and i + 1 < len(argv):
            max_issues = int(argv[i + 1])
            i += 2
            continue
        print(f"unknown arg: {argv[i]}", file=sys.stderr)
        return 2
    repo = Path(cfg.get("hellogithub_repo", "~/.hellogithub/HelloGitHub")).expanduser()
    print(f"[corpus] ingest HelloGitHub from {repo} max_issues={max_issues or 'all'}")
    meta = corpus.ingest_hellogithub(DATA_DIR, hg_repo=repo, max_issues=max_issues)
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    self_copy()
    return 0


def cmd_refresh(argv: list[str]) -> int:
    refresh_paths()
    cfg = load_config()
    ensure_data_dir(cfg)
    since = cfg.get("since", "daily")
    force = False
    intent = str(cfg.get("intent") or "")
    i = 0
    while i < len(argv):
        if argv[i] == "--since" and i + 1 < len(argv):
            since = argv[i + 1]
            i += 2
            continue
        if argv[i] == "--force":
            force = True
            i += 1
            continue
        if argv[i] == "--intent" and i + 1 < len(argv):
            intent = argv[i + 1]
            i += 2
            continue
        print(f"unknown arg: {argv[i]}", file=sys.stderr)
        return 2

    ua = cfg.get("user_agent", "skill-feed/0.1")
    ttl = float(cfg.get("ttl_hours", 6))
    min_stars, min_rel, profile = gates.resolve_thresholds(cfg)
    interest_path = Path(cfg.get("interest_from", "~/.skill-picker/catalog.json")).expanduser()
    interest_toks = rank.load_interest_tokens(interest_path)
    hg_repo = Path(cfg.get("hellogithub_repo", "~/.hellogithub/HelloGitHub")).expanduser()
    hg_max = int(cfg.get("hg_max_issues", 12))

    # 0) 增量扩充知识库（全刊，失败不阻断）
    try:
        cmeta = corpus.ingest_hellogithub(DATA_DIR, hg_repo=hg_repo, max_issues=0)
        print(f"[corpus] +{cmeta.get('added', 0)} (skipped {cmeta.get('skipped', 0)})")
    except Exception as e:  # noqa: BLE001
        print(f"[corpus] WARN: {e}")

    # 1) trending
    print(f"[refresh] fetching github.com/trending since={since} force={force}")
    repos, meta = trending.fetch_trending(
        DATA_DIR, since=since, ttl_hours=ttl, user_agent=ua, force=force,
    )
    if meta.get("warn"):
        print(f"[WARN] {meta['warn']}")
    print(f"[refresh] trending repos: {len(repos)} (cache={meta.get('from_cache')})")
    trending_names = {r.full_name for r in repos}

    shortlist = [r for r in repos if r.stars >= min_stars]
    print(f"[refresh] star shortlist (>= {min_stars}): {len(shortlist)}")
    trending_rows = [{
        "full_name": r.full_name,
        "url": r.url,
        "description": r.description,
        "language": r.language,
        "stars": r.stars,
        "stars_today": r.stars_today,
        "source": r.source,
        "kind": "skill",
    } for r in shortlist]

    # 2) HelloGitHub Skills / AI
    hg_rows = hellogithub.skill_candidates(hg_repo, max_issues=hg_max)
    print(f"[refresh] hellogithub skill/ai candidates: {len(hg_rows)}")

    # 3) GitHub Search
    search_rows: list[dict] = []
    search_meta: dict = {}
    if cfg.get("search_enabled", True):
        token = _resolve_github_token(cfg)
        try:
            search_rows, search_meta = github_search.fetch_search_candidates(
                DATA_DIR,
                user_agent=ua,
                token=token,
                ttl_hours=float(cfg.get("search_ttl_hours", 12)),
                force=force,
                per_page=int(cfg.get("search_per_page", 25)),
                max_repos=int(cfg.get("search_max_repos", 40)),
            )
        except Exception as e:  # noqa: BLE001
            search_meta = {"warn": str(e)}
            print(f"[refresh] github-search WARN: {e}")
        if search_meta.get("warn"):
            print(f"[WARN] github-search: {search_meta['warn']}")
        print(f"[refresh] github-search candidates: {len(search_rows)} (cache={search_meta.get('from_cache')})")
    else:
        print("[refresh] github-search disabled")

    # 3b) 策展目录（awesome / skills.sh 映射）
    catalog_rows: list[dict] = []
    catalog_meta: dict = {}
    if cfg.get("catalog_enabled", True):
        token = _resolve_github_token(cfg)
        try:
            catalog_rows, catalog_meta = catalog_sources.fetch_catalog_candidates(
                DATA_DIR,
                user_agent=ua,
                token=token,
                ttl_hours=float(cfg.get("catalog_ttl_hours", 24)),
                force=force,
                max_repos=int(cfg.get("catalog_max_repos", 50)),
            )
        except Exception as e:  # noqa: BLE001
            catalog_meta = {"warn": str(e)}
            print(f"[refresh] catalog WARN: {e}")
        print(
            f"[refresh] catalog candidates: {len(catalog_rows)} "
            f"(cache={catalog_meta.get('from_cache')})"
        )
    else:
        print("[refresh] catalog disabled")

    # 3c) 小红书（媒讯助手导出 / Chrome 采集落盘）
    xhs_rows: list[dict] = []
    xhs_meta: dict = {}
    if cfg.get("xhs_enabled", True):
        try:
            xhs_rows, xhs_meta = xiaohongshu.candidates_from_mentions(
                DATA_DIR, max_repos=int(cfg.get("xhs_max_repos", 30)),
            )
        except Exception as e:  # noqa: BLE001
            xhs_meta = {"warn": str(e)}
            print(f"[refresh] xiaohongshu WARN: {e}")
        print(
            f"[refresh] xiaohongshu candidates: {len(xhs_rows)} "
            f"(notes={xhs_meta.get('note_count')})"
        )
    else:
        print("[refresh] xiaohongshu disabled")

    enriched: list[dict] = []
    probed = 0
    probe_token = _resolve_github_token(cfg)
    if not probe_token:
        print("[refresh] WARN 无 GITHUB_TOKEN：api.github.com 匿名会 403，monorepo 无法展开，供给会明显偏少")
    t_enriched, t_probed = _probe_candidates(
        trending_rows, ua, always_if_skills_section=False, token=probe_token,
    )
    enriched.extend(t_enriched)
    probed += t_probed
    h_enriched, h_probed = _probe_candidates(
        hg_rows, ua, always_if_skills_section=True, token=probe_token,
    )
    enriched.extend(h_enriched)
    probed += h_probed
    force_probe = set(
        cfg.get("force_probe_repos")
        or getattr(catalog_sources, "FORCE_PROBE_REPOS", [])
    )
    expand_limit = int(cfg.get("monorepo_expand_limit", 6))

    # Search 探测：强制设计仓 + 按星数补齐
    max_search_probe = int(cfg.get("search_probe_limit", 25))
    search_probe = _pick_probe_rows(search_rows, limit=max_search_probe, force_names=force_probe)
    s_enriched, s_probed = _probe_candidates(
        search_probe, ua, always_if_skills_section=True, expand_limit=expand_limit,
        token=probe_token,
    )
    enriched.extend(s_enriched)
    probed += s_probed

    max_catalog_probe = int(cfg.get("catalog_probe_limit", 35))
    catalog_probe = _pick_probe_rows(catalog_rows, limit=max_catalog_probe, force_names=force_probe)
    c_enriched, c_probed = _probe_candidates(
        catalog_probe, ua, always_if_skills_section=True, expand_limit=expand_limit,
        token=probe_token,
    )
    enriched.extend(c_enriched)
    probed += c_probed

    max_xhs_probe = int(cfg.get("xhs_probe_limit", 20))
    xhs_probe = _pick_probe_rows(xhs_rows, limit=max_xhs_probe, force_names=force_probe)
    x_enriched, x_probed = _probe_candidates(
        xhs_probe, ua, always_if_skills_section=True, expand_limit=expand_limit,
        token=probe_token,
    )
    enriched.extend(x_enriched)
    probed += x_probed

    # 去重：同一仓可有多条 skill（按 id=full_name::skill_path）；同源择优
    source_rank = {
        "github.com/trending": 4,
        "hellogithub": 3,
        "catalog": 2,
        "github-search": 1,
        "xiaohongshu": 1,
        "corpus": 0,
    }
    by_key: dict[str, dict] = {}
    for it in enriched:
        key = _item_key(it)
        prev = by_key.get(key)
        if not prev:
            by_key[key] = it
            continue
        prev_stars = int(prev.get("stars") or 0)
        cur_stars = int(it.get("stars") or 0)
        if cur_stars > prev_stars:
            merged = dict(prev)
            merged.update({k: v for k, v in it.items() if v is not None})
            if source_rank.get(prev.get("source"), 0) >= source_rank.get(it.get("source"), 0):
                merged["source"] = prev.get("source")
            by_key[key] = merged
        elif source_rank.get(it.get("source"), 0) > source_rank.get(prev.get("source"), 0):
            merged = dict(it)
            for k, v in prev.items():
                if merged.get(k) in (None, "", 0) and v not in (None, ""):
                    merged[k] = v
            by_key[key] = merged
    enriched = list(by_key.values())
    print(f"[refresh] skill-shaped unique: {len(enriched)}")

    passed, gate_summary = gates.run_gates(
        enriched,
        trending_names=trending_names,
        min_stars=min_stars,
        min_rel=min_rel,
        interest_toks=interest_toks,
        allowed_sources=set(cfg.get("allowed_sources") or list(gates.DEFAULT_ALLOWED_SOURCES)),
        star_exempt_sources=set(
            cfg.get("star_exempt_sources")
            or ["hellogithub", "corpus", "github-search", "catalog", "xiaohongshu"]
        ),
        intent=intent,
    )
    affinity = rank.load_feedback_affinity(DATA_DIR)
    print(f"[refresh] personalize events={affinity.get('events', 0)}")

    # 写入 corpus skill 快照（过门禁的）
    try:
        sm = corpus.ingest_feed_skills(DATA_DIR, passed)
        print(f"[corpus] skills +{sm.get('added', 0)}")
    except Exception as e:  # noqa: BLE001
        print(f"[corpus] skill ingest WARN: {e}")

    corpus_rows = corpus.load_corpus_items(
        DATA_DIR, limit=int(cfg.get("corpus_feed_limit", 400)),
    )
    skill_pool = corpus.load_skill_candidates(
        DATA_DIR, limit=int(cfg.get("soft_skill_limit", 40)) * 2,
    )
    meta = dict(meta)
    meta["sources"] = {
        "trending": {"repos": len(repos), "from_cache": meta.get("from_cache")},
        "hellogithub": {"candidates": len(hg_rows)},
        "github-search": search_meta,
        "catalog": catalog_meta,
        "xiaohongshu": xhs_meta,
    }
    funnel = {
        "trending_repos": len(repos),
        "star_shortlist": len(shortlist),
        "hg_candidates": len(hg_rows),
        "search_candidates": len(search_rows),
        "catalog_candidates": len(catalog_rows),
        "xhs_candidates": len(xhs_rows),
        "probed": probed,
        "skill_shaped": len(enriched),
        "passed": len(passed),
    }
    feed = feed_pack.pack_feed(
        passed=passed,
        corpus_rows=corpus_rows,
        meta=meta,
        gates_summary=gate_summary,
        funnel=funnel,
        affinity=affinity,
        intent=intent,
        config={
            "min_stars": min_stars,
            "min_rel": min_rel,
            "since": since,
            "gate_profile": profile,
            "intent": intent,
        },
        soft_limit=int(cfg.get("soft_skill_limit", 40)),
        skill_pool=skill_pool,
    )
    feed["generated_at"] = datetime.now(timezone.utc).isoformat()
    run_i18n(feed, cfg)
    retag_scenes(feed)
    FEED_JSON.write_text(json.dumps(feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_local_feed_pages(feed)
    self_copy()

    print(f"[refresh] stream items: {len(feed.get('items') or [])} (passed={len(passed)} + soft)")
    print(f"[refresh] rejected: {gate_summary.get('rejected')}")
    print(f"[refresh] funnel: {feed.get('funnel')}")
    print(f"[refresh] wrote {FEED_JSON}")
    print(f"[refresh] wrote {FEED_HTML}")
    print(f"[refresh] wrote {FEED_HTML_LITE} (lite · skill-picker)")
    return 0


def cmd_build(argv: list[str]) -> int:
    """不联网：用现有 feed.json / corpus 重打包 + 重生竖滑信息流 HTML。"""
    refresh_paths()
    cfg = load_config()
    ensure_data_dir(cfg)
    intent = str(cfg.get("intent") or "")
    i = 0
    while i < len(argv):
        if argv[i] == "--intent" and i + 1 < len(argv):
            intent = argv[i + 1]
            i += 2
            continue
        print(f"unknown arg: {argv[i]}", file=sys.stderr)
        return 2

    affinity = rank.load_feedback_affinity(DATA_DIR)
    old: dict = {}
    if FEED_JSON.exists():
        try:
            old = json.loads(FEED_JSON.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            old = {}

    # 优先用旧 feed 的 live 项作 passed；再并 corpus
    passed = []
    for it in (old.get("items") or []):
        if it.get("soft"):
            continue
        passed.append(it)
    passed = corpus.attach_body_previews(DATA_DIR, passed)
    corpus_rows = corpus.load_corpus_items(DATA_DIR, limit=int(cfg.get("corpus_feed_limit", 400)))
    if not corpus_rows and old.get("corpus"):
        corpus_rows = list(old.get("corpus") or [])
    corpus_rows = corpus.attach_body_previews(DATA_DIR, corpus_rows)
    skill_pool = corpus.load_skill_candidates(
        DATA_DIR, limit=int(cfg.get("soft_skill_limit", 40)) * 2,
    )
    skill_pool = corpus.attach_body_previews(DATA_DIR, skill_pool)

    feed = feed_pack.pack_feed(
        passed=passed,
        corpus_rows=corpus_rows,
        meta=old.get("meta") or {"source": "local-build"},
        gates_summary=old.get("gates") or {},
        funnel=old.get("funnel") or {},
        affinity=affinity,
        intent=intent,
        config={**(old.get("config") or {}), "intent": intent},
        soft_limit=int(cfg.get("soft_skill_limit", 40)),
        skill_pool=skill_pool,
    )
    feed["generated_at"] = datetime.now(timezone.utc).isoformat()
    run_i18n(feed, cfg)
    retag_scenes(feed)
    FEED_JSON.write_text(json.dumps(feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_local_feed_pages(feed)
    self_copy()
    print(f"[build] items={len(feed.get('items') or [])} corpus={len(feed.get('corpus') or [])}")
    print(f"[build] wrote {FEED_HTML}")
    print(f"[build] wrote {FEED_HTML_LITE} (lite · skill-picker)")
    return 0


def cmd_publish_site(argv: list[str]) -> int:
    """导出独立网页产物：site/index.html（full）+ site/embed.html（lite）+ feed.json。"""
    refresh_paths()
    out = Path("site")
    i = 0
    while i < len(argv):
        if argv[i] in ("--out", "-o") and i + 1 < len(argv):
            out = Path(argv[i + 1])
            i += 2
            continue
        print(f"unknown arg: {argv[i]}", file=sys.stderr)
        return 2

    if not FEED_JSON.exists():
        print("no feed.json — run: python skillfeed.py refresh", file=sys.stderr)
        return 1
    try:
        feed = json.loads(FEED_JSON.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"bad feed.json: {e}", file=sys.stderr)
        return 1

    ui = dict(feed.get("ui") or {})
    ui["hosting"] = "pages"
    ui["feedback"] = "local-only"
    ui["cta"] = ui.get("cta") or "open_github"
    ui["variant"] = "full"
    api_base = (os.environ.get("SKILLFEED_PUBLIC_URL") or ui.get("api_base") or "").strip().rstrip("/")
    if api_base:
        ui["api_base"] = api_base
    feed["ui"] = ui

    out.mkdir(parents=True, exist_ok=True)
    (out / ".nojekyll").write_text("", encoding="utf-8")

    # 自有域名要靠 artifact 里的 CNAME 告诉 Pages，放仓库根没用——上传的是 site/。
    #
    # 顺序有个坑：Pages 一旦认了自有域名，就会把 <user>.github.io/<repo> 301 重定向
    # 过去。所以 DNS 没就位就写这个文件，等于两个地址一起死。因此默认不写，
    # DNS 生效之后再置 SKILLFEED_SITE_DOMAIN 打开。
    domain = (os.environ.get("SKILLFEED_SITE_DOMAIN") or "").strip().lstrip(".")
    if domain:
        (out / "CNAME").write_text(domain + "\n", encoding="utf-8")
        print(f"[publish-site] wrote {out.resolve()}/CNAME ({domain})")
    (out / "feed.json").write_text(
        json.dumps(feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    feed_dashboard.write_feed_html(feed, out / "index.html", variant="full")
    lite_feed = dict(feed)
    lite_ui = dict(ui)
    lite_ui["variant"] = "lite"
    lite_ui.pop("api_base", None)
    lite_feed["ui"] = lite_ui
    feed_dashboard.write_feed_html(lite_feed, out / "embed.html", variant="lite")
    (out / "BUILD.txt").write_text(
        "skill-feed static web product\n"
        "index.html = full site (updates ring/follow/publish when api_base set)\n"
        "embed.html = lite for skill-picker (no follow/publish/me)\n"
        f"generated_at={feed.get('generated_at')}\n"
        f"items={len(feed.get('items') or [])}\n"
        f"corpus={len(feed.get('corpus') or [])}\n",
        encoding="utf-8",
    )
    print(f"[publish-site] wrote {out.resolve()}/index.html (full web)")
    print(f"[publish-site] wrote {out.resolve()}/embed.html (lite embed)")
    print(f"[publish-site] items={len(feed.get('items') or [])} corpus={len(feed.get('corpus') or [])}")
    return 0


def cmd_api(argv: list[str]) -> int:
    """启动 FastAPI：GitHub 登录 + UGC 发布 + 混排 Feed。"""
    root = Path(__file__).resolve().parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    host = "127.0.0.1"
    port = 8787
    reload = False
    i = 0
    while i < len(argv):
        if argv[i] == "--host" and i + 1 < len(argv):
            host = argv[i + 1]
            i += 2
            continue
        if argv[i] == "--port" and i + 1 < len(argv):
            port = int(argv[i + 1])
            i += 2
            continue
        if argv[i] == "--reload":
            reload = True
            i += 1
            continue
        print(f"unknown arg: {argv[i]}", file=sys.stderr)
        return 2
    try:
        import uvicorn
    except ImportError:
        print(
            "缺少服务端依赖。请先安装：\n  pip install -r requirements-server.txt",
            file=sys.stderr,
        )
        return 1
    print(f"[api] skill-feed API → http://{host}:{port}/")
    print("[api] publish UI → /publish · docs → /docs")
    uvicorn.run("server.app:app", host=host, port=port, reload=reload)
    return 0


def cmd_check(_: list[str]) -> int:
    refresh_paths()
    cfg = load_config()
    if not FEED_JSON.exists():
        print("no feed.json — run: python skillfeed.py refresh")
        return 2
    feed = json.loads(FEED_JSON.read_text(encoding="utf-8"))
    gates_s = feed.get("gates") or {}
    funnel = feed.get("funnel") or {}
    print(f"generated_at: {feed.get('generated_at')}")
    print(f"source: {(feed.get('meta') or {}).get('source')}")
    print(f"since: {(feed.get('meta') or {}).get('since')}")
    print(f"from_cache: {(feed.get('meta') or {}).get('from_cache')}")
    warn = (feed.get("meta") or {}).get("warn")
    if warn:
        print(f"WARN: {warn}")
    print(f"items: {len(feed.get('items') or [])}")
    print(f"corpus: {len(feed.get('corpus') or [])}")
    print(f"funnel: {funnel}")
    print(f"gates.input: {gates_s.get('input')}")
    print(f"gates.passed: {gates_s.get('passed')}")
    print(f"gates.rejected: {gates_s.get('rejected')}")
    print(f"config: min_stars={cfg.get('min_stars')} min_rel={cfg.get('min_rel')} profile={cfg.get('gate_profile')}")
    if warn and not feed.get("items") and not feed.get("corpus"):
        return 2
    return 0


def cmd_feedback(_: list[str]) -> int:
    print(json.dumps(feedback.summarize(DATA_DIR), ensure_ascii=False, indent=2))
    return 0


class FeedHandler(BaseHTTPRequestHandler):
    cfg: dict = {}

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/feed.html", "/index.html"):
            target = FEED_HTML if FEED_HTML.exists() else None
            if not target:
                self._json(404, {"ok": False, "error": "feed.html missing; run refresh"})
                return
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/feed.json":
            if not FEED_JSON.exists():
                self._json(404, {"ok": False, "error": "feed.json missing"})
                return
            data = FEED_JSON.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if path == "/api/feedback":
            self._json(200, feedback.summarize(DATA_DIR))
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/feedback":
            self._json(404, {"ok": False, "error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"ok": False, "error": "invalid json"})
            return
        result = feedback.append_feedback(DATA_DIR, payload if isinstance(payload, dict) else {})
        self._json(200 if result.get("ok") else 400, result)


def cmd_serve(argv: list[str]) -> int:
    refresh_paths()
    cfg = load_config()
    ensure_data_dir(cfg)
    self_copy()
    # 每次 serve 用最新板式重生 HTML（不强制联网）
    if FEED_JSON.exists() or corpus.corpus_root(DATA_DIR).exists():
        print("[serve] rebuilding feed from local data...")
        cmd_build([])
    elif not FEED_HTML.exists():
        print("[serve] no local feed — running refresh first...")
        rc = cmd_refresh([])
        if rc != 0 and not FEED_HTML.exists():
            return rc
    port = 8473
    open_browser = True
    i = 0
    while i < len(argv):
        if argv[i] == "--port" and i + 1 < len(argv):
            port = int(argv[i + 1])
            i += 2
            continue
        if argv[i] == "--no-browser":
            open_browser = False
            i += 1
            continue
        print(f"unknown arg: {argv[i]}", file=sys.stderr)
        return 2

    FeedHandler.cfg = cfg
    httpd = None
    last_err = None
    for p in range(port, port + 10):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), FeedHandler)
            port = p
            break
        except OSError as e:
            last_err = e
    if httpd is None:
        print(f"cannot bind port: {last_err}", file=sys.stderr)
        return 1
    url = f"http://127.0.0.1:{port}/"
    print(f"[serve] skill 信息流 → {url}")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[serve] stopped")
    return 0


def cmd_i18n(argv: list[str]) -> int:
    """只补双语人话字段：不联网采集，直接改写现有 feed.json 并重生 HTML。"""
    refresh_paths()
    cfg = load_config()
    ensure_data_dir(cfg)
    force = False
    i = 0
    while i < len(argv):
        if argv[i] == "--force":
            force = True
            i += 1
            continue
        if argv[i] == "--limit" and i + 1 < len(argv):
            cfg["i18n_limit"] = int(argv[i + 1])
            i += 2
            continue
        if argv[i] == "--model" and i + 1 < len(argv):
            cfg["i18n_model"] = argv[i + 1]
            i += 2
            continue
        print(f"unknown arg: {argv[i]}", file=sys.stderr)
        return 2

    if not FEED_JSON.exists():
        print(f"没有 {FEED_JSON}，先跑 refresh 或 build", file=sys.stderr)
        return 1
    try:
        feed = json.loads(FEED_JSON.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"读取 feed.json 失败: {e}", file=sys.stderr)
        return 1

    run_i18n(feed, cfg, force=force)
    retag_scenes(feed)
    FEED_JSON.write_text(json.dumps(feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_local_feed_pages(feed)
    self_copy()
    print(f"[i18n] wrote {FEED_JSON}")
    print(f"[i18n] wrote {FEED_HTML}")
    print(f"[i18n] wrote {FEED_HTML_LITE}")
    return 0


def cmd_bitable(argv: list[str]) -> int:
    """译稿库：init 建表 / pull 拉回验收结果 / push 上传新译稿 / sync 一次做完。"""
    refresh_paths()
    cfg = load_config()
    ensure_data_dir(cfg)
    if not argv:
        print(
            "用法: bitable init --base-token TOKEN | pull | push | sync | dedupe",
            file=sys.stderr,
        )
        return 2
    sub, rest = argv[0], argv[1:]

    base_token = ""
    i = 0
    while i < len(rest):
        if rest[i] == "--base-token" and i + 1 < len(rest):
            base_token = rest[i + 1]
            i += 2
            continue
        print(f"unknown arg: {rest[i]}", file=sys.stderr)
        return 2

    if sub == "init":
        base_token = base_token or str(cfg.get("bitable_base_token") or "")
        if not base_token:
            print(
                "缺 --base-token。可在 ~/.skill-feed/config.json 写 bitable_base_token",
                file=sys.stderr,
            )
            return 2
        bt, tid = bitable_store.init_table(DATA_DIR, base_token)
        print(f"[bitable] 译稿库就绪 base_token={bt} table_id={tid}")
        return 0

    if sub == "pull":
        s = bitable_store.pull(DATA_DIR)
        print(
            f"[bitable] pull 远端={s['remote']} 可用={s['usable']} "
            f"已验收={s['accepted']} 需重译={s['redo']} 重复键={s['dupes']}"
        )
        if s["dupes"]:
            print("[bitable] 有重复行，可跑 `bitable dedupe` 清理")
        return 0

    if sub == "dedupe":
        s = bitable_store.dedupe(DATA_DIR)
        print(f"[bitable] dedupe 唯一键={s['keys']} 删除重复={s['deleted']}")
        return 0

    if sub in ("push", "sync"):
        if not FEED_JSON.exists():
            print(f"没有 {FEED_JSON}，先跑 refresh 或 build", file=sys.stderr)
            return 1
        feed = json.loads(FEED_JSON.read_text(encoding="utf-8"))
        if sub == "sync":
            s = bitable_store.pull(DATA_DIR)
            print(
                f"[bitable] pull 远端={s['remote']} 可用={s['usable']} "
                f"已验收={s['accepted']} 需重译={s['redo']}"
            )
            run_i18n(feed, cfg)
            retag_scenes(feed)
            FEED_JSON.write_text(
                json.dumps(feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            write_local_feed_pages(feed)
        p = bitable_store.push(
            DATA_DIR, feed, model=str(cfg.get("i18n_model") or i18n.DEFAULT_MODEL)
        )
        print(
            f"[bitable] push 新建={p['created']} 更新={p['updated']} "
            f"跳过已验收={p['skipped_accepted']} 无译稿={p['no_fields']} "
            f"同键去重={p['deduped']}"
        )
        return 0

    print(f"unknown bitable subcommand: {sub}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd = argv[0]
    rest = argv[1:]
    if cmd == "refresh":
        return cmd_refresh(rest)
    if cmd == "build":
        return cmd_build(rest)
    if cmd == "i18n":
        return cmd_i18n(rest)
    if cmd == "bitable":
        return cmd_bitable(rest)
    if cmd == "corpus":
        return cmd_corpus(rest)
    if cmd == "xhs-crawl":
        return cmd_xhs_crawl(rest)
    if cmd == "check":
        return cmd_check(rest)
    if cmd == "feedback":
        return cmd_feedback(rest)
    if cmd == "publish-site":
        return cmd_publish_site(rest)
    if cmd == "api":
        return cmd_api(rest)
    if cmd == "serve":
        return cmd_serve(rest)
    if cmd == "install":
        print("install 已移除：skill-feed 只推荐到 GitHub，请自行克隆/安装后再用 skill-picker scan", file=sys.stderr)
        return 2
    print(f"unknown command: {cmd}", file=sys.stderr)
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
