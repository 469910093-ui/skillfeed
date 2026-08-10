"""策展目录源：awesome lists / 官方 skills 仓 / skills.sh 热榜映射。

产出与 github-search 对齐的 repo 候选行，供 refresh 探测 SKILL.md。
纯标准库，无第三方依赖。
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SOURCE = "catalog"

# 高信号策展仓：本身常含多技能，或 README 链出大量 skill 仓
DEFAULT_SEED_REPOS = [
    "anthropics/skills",
    "vercel-labs/agent-skills",
    "VoltAgent/awesome-agent-skills",
    "ComposioHQ/awesome-claude-skills",
    "travisvn/awesome-claude-skills",
    "JackyST0/awesome-agent-skills",
    "addyosmani/agent-skills",
    "hesreallyhim/awesome-claude-code",
    "sickn33/agentic-awesome-skills",
    "wshobson/agents",
    "microsoft/azure-skills",
    "larksuite/cli",
    "prisma/skills",
    "superpowers-ai/superpowers",
    "obra/superpowers",
]

# 从 README 抽链接时优先抓这些宿主仓的 README
README_HOSTS = [
    "VoltAgent/awesome-agent-skills",
    "JackyST0/awesome-agent-skills",
    "ComposioHQ/awesome-claude-skills",
    "travisvn/awesome-claude-skills",
    "hesreallyhim/awesome-claude-code",
]

# skills.sh 公开热榜上常见的可解析 GitHub 仓（人工映射，避免依赖未公开 API）
SKILLS_SH_HOT = [
    "vercel-labs/agent-skills",
    "anthropics/skills",
    "obra/superpowers",
    "mattpocock/skills",
    "larksuite/cli",
    "microsoft/azure-skills",
    "heygen-com/hyperframes",
    "JuliusBrussee/caveman",
    "hardikpandya/stop-slop",
    "supabase/agent-skills",
    "remotion-dev/skills",
    "prisma/skills",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _headers(user_agent: str, token: str = "") -> dict[str, str]:
    h = {
        "User-Agent": user_agent,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _http_text(url: str, user_agent: str, token: str = "", timeout: int = 30) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=_headers(user_agent, token))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode(resp.headers.get_content_charset() or "utf-8", errors="replace")
            return resp.status, raw
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return 0, str(e)


def _http_json(url: str, user_agent: str, token: str = "", timeout: int = 30) -> tuple[int, Any]:
    code, raw = _http_text(url, user_agent, token=token, timeout=timeout)
    try:
        return code, json.loads(raw) if raw else None
    except json.JSONDecodeError:
        return code, None


def _cache_path(data_dir: Path) -> Path:
    return data_dir / "cache" / "catalog_sources.json"


def _load_cache(data_dir: Path, ttl_hours: float) -> Optional[dict]:
    path = _cache_path(data_dir)
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    ts = obj.get("fetched_at") or ""
    try:
        fetched = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        age_h = (datetime.now(timezone.utc) - fetched).total_seconds() / 3600.0
        if age_h <= ttl_hours:
            return obj
    except (TypeError, ValueError):
        return None
    return None


def _save_cache(data_dir: Path, payload: dict) -> None:
    path = _cache_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


_GH_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.I,
)
_PATH_SEGMENTS = frozenset({
    "blob", "tree", "issues", "pull", "releases", "wiki", "actions",
    "commit", "commits", "pulse", "security", "projects", "packages",
})


def extract_github_full_names(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in _GH_RE.finditer(text or ""):
        owner, repo = m.group(1), m.group(2)
        if owner.lower() in {"topics", "settings", "orgs", "marketplace", "sponsors"}:
            continue
        if repo.lower() in _PATH_SEGMENTS:
            continue
        fn = f"{owner}/{repo}"
        key = fn.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(fn)
    return out


def _repo_api(full_name: str, user_agent: str, token: str) -> Optional[dict]:
    code, data = _http_json(
        f"https://api.github.com/repos/{full_name}",
        user_agent,
        token=token,
    )
    if code != 200 or not isinstance(data, dict):
        return None
    return {
        "full_name": data.get("full_name") or full_name,
        "url": data.get("html_url") or f"https://github.com/{full_name}",
        "description": data.get("description") or "",
        "language": data.get("language") or "",
        "stars": int(data.get("stargazers_count") or 0),
        "stars_today": 0,
        "source": SOURCE,
        "kind": "skill",
        "catalog_hint": "seed",
    }


def _readme_raw(full_name: str, user_agent: str, token: str) -> str:
    # 优先 raw.githubusercontent main/master README
    for branch in ("main", "master"):
        for name in ("README.md", "readme.md"):
            url = f"https://raw.githubusercontent.com/{full_name}/{branch}/{name}"
            code, text = _http_text(url, user_agent, token="")
            if code == 200 and text and len(text) > 200:
                return text
    # API fallback
    code, data = _http_json(
        f"https://api.github.com/repos/{full_name}/readme",
        user_agent,
        token=token,
    )
    if code == 200 and isinstance(data, dict) and data.get("download_url"):
        c2, text = _http_text(str(data["download_url"]), user_agent, token="")
        if c2 == 200:
            return text
    return ""


def fetch_catalog_candidates(
    data_dir: Path,
    *,
    user_agent: str,
    token: str = "",
    ttl_hours: float = 24,
    force: bool = False,
    max_repos: int = 60,
    readme_hosts: Optional[list[str]] = None,
    seed_repos: Optional[list[str]] = None,
) -> tuple[list[dict], dict]:
    if not force:
        cached = _load_cache(data_dir, ttl_hours)
        if cached and cached.get("items") is not None:
            meta = dict(cached.get("meta") or {})
            meta["from_cache"] = True
            return list(cached["items"]), meta

    token = (token or "").strip()
    seeds = list(seed_repos or DEFAULT_SEED_REPOS)
    hosts = list(readme_hosts or README_HOSTS)
    hot = list(SKILLS_SH_HOT)

    names: list[str] = []
    seen: set[str] = set()

    def push(fn: str) -> None:
        key = (fn or "").strip().lower()
        if not key or "/" not in key or key in seen:
            return
        seen.add(key)
        names.append(fn.strip())

    for fn in seeds + hot:
        push(fn)

    meta: dict[str, Any] = {
        "from_cache": False,
        "fetched_at": _now(),
        "source": SOURCE,
        "readme_hosts": [],
        "extracted": 0,
    }

    for host in hosts:
        text = _readme_raw(host, user_agent, token)
        meta["readme_hosts"].append({"repo": host, "bytes": len(text)})
        for fn in extract_github_full_names(text):
            push(fn)
            meta["extracted"] += 1
        time.sleep(0.2)

    # 限流：优先 seed/hot，再 README 抽出的
    priority = {fn.lower(): i for i, fn in enumerate(seeds + hot)}
    names.sort(key=lambda fn: (priority.get(fn.lower(), 10_000), fn.lower()))
    names = names[: max(max_repos * 2, max_repos)]

    items: list[dict] = []
    api_ok = 0
    for fn in names:
        if len(items) >= max_repos:
            break
        if token:
            row = _repo_api(fn, user_agent, token)
            if row:
                api_ok += 1
                items.append(row)
                time.sleep(0.15)
                continue
        # 无 token / API 失败：仍保留候选，星数未知，门禁 star_exempt
        items.append({
            "full_name": fn,
            "url": f"https://github.com/{fn}",
            "description": f"Catalog / skills.sh curated: {fn}",
            "language": "",
            "stars": None,
            "stars_today": 0,
            "source": SOURCE,
            "kind": "skill",
            "catalog_hint": "seed-or-readme",
        })

    meta["api_enriched"] = api_ok
    meta["returned"] = len(items)
    if not token:
        meta["note"] = "未配置 token：catalog 候选未补全 stars"

    payload = {"fetched_at": _now(), "items": items, "meta": meta}
    _save_cache(data_dir, payload)
    return items, meta
