#!/usr/bin/env python3
"""skill-feed: 多源发现 → 门禁 → 无限下滑 Feed → 打开 GitHub（不代装）。

与 skill-picker 拆产品线：本工具负责联网发现与离线知识库；
skill-picker 继续只做 100% 本地扫描/匹配。

用法:
  python skillfeed.py refresh [--since daily|weekly] [--force] [--intent TEXT]
  python skillfeed.py build [--intent TEXT]   # 用已有 feed/corpus 重生信息流 HTML
  python skillfeed.py corpus [--max-issues N]
  python skillfeed.py publish-site [--out DIR]  # 导出静态站（GitHub Pages）
  python skillfeed.py api [--host HOST] [--port N]  # 云端 API：登录 + UGC
  python skillfeed.py serve [--port N]
  python skillfeed.py check
  python skillfeed.py feedback

环境变量:
  SKILLFEED_HOME  数据目录（默认 ~/.skill-feed；CI 可设为仓库内路径）
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
from urllib.parse import urlparse

import corpus
import feedback
import feed_dashboard
import feed_pack
import gates
import github_search
import hellogithub
import rank
import scene
import skill_detect
import trending

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
CONFIG_JSON = DATA_DIR / "config.json"


def refresh_paths() -> None:
    """SKILLFEED_HOME 在进程内被设置后，同步模块级路径。"""
    global DATA_DIR, FEED_JSON, FEED_HTML, CONFIG_JSON
    DATA_DIR = data_dir()
    FEED_JSON = DATA_DIR / "feed.json"
    FEED_HTML = DATA_DIR / "feed.html"
    CONFIG_JSON = DATA_DIR / "config.json"
TOOL_FILES = [
    "skillfeed.py",
    "trending.py",
    "skill_detect.py",
    "gates.py",
    "rank.py",
    "feed_dashboard.py",
    "hellogithub.py",
    "github_search.py",
    "corpus.py",
    "feed_pack.py",
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


def _probe_candidates(
    rows: list[dict],
    ua: str,
    *,
    always_if_skills_section: bool = True,
    always_probe_all: bool = False,
) -> tuple[list[dict], int]:
    enriched: list[dict] = []
    probed = 0
    for r in rows:
        always = always_probe_all or skill_detect.looks_like_skill_repo(
            r.get("description") or "", r.get("full_name") or "",
        )
        if always_if_skills_section and (r.get("hg_section") == "Skills" or r.get("kind") == "skill"):
            always = True
        if r.get("source") == "github-search":
            always = True
        probed += 1
        try:
            item = skill_detect.enrich_repo(r, ua, always_probe=always)
        except Exception as e:  # noqa: BLE001
            print(f"[refresh] skip {r.get('full_name')}: {e}")
            continue
        if item:
            enriched.append(item)
            print(f"[refresh] skill hit: {item.get('full_name')} <- {item.get('source')}")
    return enriched, probed


def _resolve_github_token(cfg: dict) -> str:
    return (
        (cfg.get("github_token") or "").strip()
        or os.environ.get("GITHUB_TOKEN", "").strip()
        or os.environ.get("GH_TOKEN", "").strip()
    )


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

    enriched: list[dict] = []
    probed = 0
    t_enriched, t_probed = _probe_candidates(trending_rows, ua, always_if_skills_section=False)
    enriched.extend(t_enriched)
    probed += t_probed
    h_enriched, h_probed = _probe_candidates(hg_rows, ua, always_if_skills_section=True)
    enriched.extend(h_enriched)
    probed += h_probed
    # Search 探测限流：按星数优先，避免刷爆 API
    max_search_probe = int(cfg.get("search_probe_limit", 15))
    search_probe = sorted(
        search_rows,
        key=lambda x: int(x.get("stars") or 0),
        reverse=True,
    )[:max_search_probe]
    s_enriched, s_probed = _probe_candidates(search_probe, ua, always_if_skills_section=True)
    enriched.extend(s_enriched)
    probed += s_probed

    # 去重 full_name（优先更高 stars；trending > hellogithub > search）
    source_rank = {
        "github.com/trending": 3,
        "hellogithub": 2,
        "github-search": 1,
        "corpus": 0,
    }
    by_name: dict[str, dict] = {}
    for it in enriched:
        fn = it.get("full_name") or ""
        prev = by_name.get(fn)
        if not prev:
            by_name[fn] = it
            continue
        prev_stars = int(prev.get("stars") or 0)
        cur_stars = int(it.get("stars") or 0)
        if cur_stars > prev_stars:
            merged = dict(prev)
            merged.update({k: v for k, v in it.items() if v is not None})
            # 保留更高优先级 source 标签作主 source，但附带 sources 列表
            if source_rank.get(prev.get("source"), 0) >= source_rank.get(it.get("source"), 0):
                merged["source"] = prev.get("source")
            by_name[fn] = merged
        elif source_rank.get(it.get("source"), 0) > source_rank.get(prev.get("source"), 0):
            merged = dict(it)
            for k, v in prev.items():
                if merged.get(k) in (None, "", 0) and v not in (None, ""):
                    merged[k] = v
            by_name[fn] = merged
    enriched = list(by_name.values())
    print(f"[refresh] skill-shaped unique: {len(enriched)}")

    passed, gate_summary = gates.run_gates(
        enriched,
        trending_names=trending_names,
        min_stars=min_stars,
        min_rel=min_rel,
        interest_toks=interest_toks,
        allowed_sources=set(cfg.get("allowed_sources") or list(gates.DEFAULT_ALLOWED_SOURCES)),
        star_exempt_sources=set(cfg.get("star_exempt_sources") or ["hellogithub", "corpus", "github-search"]),
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
    }
    funnel = {
        "trending_repos": len(repos),
        "star_shortlist": len(shortlist),
        "hg_candidates": len(hg_rows),
        "search_candidates": len(search_rows),
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
    FEED_JSON.write_text(json.dumps(feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    feed_dashboard.write_feed_html(feed, FEED_HTML)
    self_copy()

    print(f"[refresh] stream items: {len(feed.get('items') or [])} (passed={len(passed)} + soft)")
    print(f"[refresh] rejected: {gate_summary.get('rejected')}")
    print(f"[refresh] funnel: {feed.get('funnel')}")
    print(f"[refresh] wrote {FEED_JSON}")
    print(f"[refresh] wrote {FEED_HTML}")
    return 0


def cmd_build(argv: list[str]) -> int:
    """不联网：用现有 feed.json / corpus 重打包 + 重生 Instagram 信息流 HTML。"""
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
    FEED_JSON.write_text(json.dumps(feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    feed_dashboard.write_feed_html(feed, FEED_HTML)
    self_copy()
    print(f"[build] items={len(feed.get('items') or [])} corpus={len(feed.get('corpus') or [])}")
    print(f"[build] wrote {FEED_HTML}")
    return 0


def cmd_publish_site(argv: list[str]) -> int:
    """把最新 Feed 导出为可部署的静态站点（index.html + feed.json）。"""
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
    feed["ui"] = ui

    out.mkdir(parents=True, exist_ok=True)
    (out / ".nojekyll").write_text("", encoding="utf-8")
    (out / "feed.json").write_text(
        json.dumps(feed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    feed_dashboard.write_feed_html(feed, out / "index.html")
    # 简短说明（不参与站点路由）
    (out / "BUILD.txt").write_text(
        "skill-feed static site\n"
        f"generated_at={feed.get('generated_at')}\n"
        f"items={len(feed.get('items') or [])}\n"
        f"corpus={len(feed.get('corpus') or [])}\n",
        encoding="utf-8",
    )
    print(f"[publish-site] wrote {out.resolve()}/index.html")
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
        print("[serve] rebuilding Instagram feed from local data...")
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
    if cmd == "corpus":
        return cmd_corpus(rest)
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
