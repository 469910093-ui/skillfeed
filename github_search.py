"""GitHub Search 源：召回含 SKILL.md 的仓库（补全 trending / HelloGitHub）。"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

SOURCE = "github-search"

# 无 token 时用仓库搜索兜底；有 token 优先 code search
DEFAULT_REPO_QUERIES = [
    'filename:SKILL.md',  # 部分环境仍可用；失败则忽略
    '"SKILL.md" in:readme',
    '"agent skills" OR "claude skill" OR "cursor skill"',
    "topic:claude-skills OR topic:agent-skills",
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


def _http_json(url: str, user_agent: str, token: str = "", timeout: int = 30) -> tuple[int, Any, dict]:
    req = urllib.request.Request(url, headers=_headers(user_agent, token))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode(resp.headers.get_content_charset() or "utf-8", errors="replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            try:
                return resp.status, json.loads(raw), headers
            except json.JSONDecodeError:
                return resp.status, None, headers
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            data = json.loads(body) if body else None
        except json.JSONDecodeError:
            data = {"message": body[:300]}
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, data, headers
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return 0, {"message": str(e)}, {}


def _cache_path(data_dir: Path) -> Path:
    return data_dir / "cache" / "github_search.json"


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


def _repo_row(repo: dict) -> Optional[dict]:
    full_name = repo.get("full_name") or ""
    if "/" not in full_name:
        return None
    return {
        "full_name": full_name,
        "url": repo.get("html_url") or f"https://github.com/{full_name}",
        "description": repo.get("description") or "",
        "language": repo.get("language") or "",
        "stars": int(repo.get("stargazers_count") or 0),
        "stars_today": 0,
        "source": SOURCE,
        "kind": "skill",
        "search_score": float(repo.get("score") or 0),
    }


def search_code_skill_md(
    user_agent: str,
    token: str,
    *,
    per_page: int = 30,
) -> tuple[list[dict], dict]:
    """需要 token。q=filename:SKILL.md"""
    q = "filename:SKILL.md"
    url = "https://api.github.com/search/code?" + urllib.parse.urlencode({
        "q": q,
        "per_page": str(per_page),
    })
    code, data, headers = _http_json(url, user_agent, token=token)
    meta = {
        "endpoint": "search/code",
        "status": code,
        "remaining": headers.get("x-ratelimit-remaining"),
    }
    if code != 200 or not isinstance(data, dict):
        meta["warn"] = (data or {}).get("message") if isinstance(data, dict) else f"http {code}"
        return [], meta
    rows: list[dict] = []
    seen: set[str] = set()
    for item in data.get("items") or []:
        repo = item.get("repository") or {}
        row = _repo_row(repo)
        if not row:
            continue
        fn = row["full_name"]
        if fn in seen:
            continue
        seen.add(fn)
        # code search 常无 stars，稍后可用 repo API；先记 0
        if row["stars"] == 0 and "stargazers_count" not in repo:
            row["stars"] = None
        path = item.get("path") or "SKILL.md"
        row["skill_path_hint"] = path
        rows.append(row)
    meta["total_count"] = data.get("total_count")
    meta["returned"] = len(rows)
    return rows, meta


def search_repos(
    user_agent: str,
    token: str = "",
    *,
    queries: Optional[list[str]] = None,
    per_page: int = 20,
    sleep_s: float = 0.4,
) -> tuple[list[dict], dict]:
    """仓库搜索兜底（可无 token，限额更紧）。"""
    qs = queries or DEFAULT_REPO_QUERIES[1:]  # 跳过 filename 伪查询
    rows: list[dict] = []
    seen: set[str] = set()
    warns: list[str] = []
    statuses: list[int] = []
    for q in qs:
        url = "https://api.github.com/search/repositories?" + urllib.parse.urlencode({
            "q": q,
            "sort": "stars",
            "order": "desc",
            "per_page": str(per_page),
        })
        code, data, headers = _http_json(url, user_agent, token=token)
        statuses.append(code)
        if code == 403:
            warns.append("rate limited on search/repositories")
            break
        if code != 200 or not isinstance(data, dict):
            msg = (data or {}).get("message") if isinstance(data, dict) else f"http {code}"
            warns.append(f"{q}: {msg}")
            continue
        for repo in data.get("items") or []:
            row = _repo_row(repo)
            if not row:
                continue
            fn = row["full_name"]
            if fn in seen:
                continue
            seen.add(fn)
            row["search_query"] = q
            rows.append(row)
        time.sleep(sleep_s)
    meta = {
        "endpoint": "search/repositories",
        "statuses": statuses,
        "returned": len(rows),
        "warn": "; ".join(warns) if warns else "",
    }
    return rows, meta


def fetch_search_candidates(
    data_dir: Path,
    *,
    user_agent: str,
    token: str = "",
    ttl_hours: float = 12,
    force: bool = False,
    per_page: int = 25,
    max_repos: int = 40,
) -> tuple[list[dict], dict]:
    """
    拉取 GitHub Search 候选。优先缓存；有 token 先 code search，再补仓库搜索。
    """
    if not force:
        cached = _load_cache(data_dir, ttl_hours)
        if cached and cached.get("items") is not None:
            meta = dict(cached.get("meta") or {})
            meta["from_cache"] = True
            return list(cached["items"]), meta

    items: list[dict] = []
    meta: dict[str, Any] = {"from_cache": False, "fetched_at": _now(), "source": SOURCE}
    token = (token or "").strip()

    if token:
        code_rows, code_meta = search_code_skill_md(user_agent, token, per_page=per_page)
        meta["code_search"] = code_meta
        items.extend(code_rows)
    else:
        meta["code_search"] = {"skipped": True, "reason": "no github_token / GITHUB_TOKEN"}

    # 仓库搜索补全（无/有 token 都可试）
    repo_rows, repo_meta = search_repos(
        user_agent, token=token, per_page=min(per_page, 20),
    )
    meta["repo_search"] = repo_meta
    seen = {r["full_name"] for r in items}
    for r in repo_rows:
        if r["full_name"] in seen:
            continue
        seen.add(r["full_name"])
        items.append(r)

    items = items[:max_repos]
    if repo_meta.get("warn") and not items:
        meta["warn"] = repo_meta["warn"]
    elif not token and not items:
        meta["warn"] = "GitHub Search 无结果；可设置 GITHUB_TOKEN 或 config.github_token 启用 code search"
    elif not token:
        meta.setdefault("note", "未配置 token：仅用 repositories 搜索，召回偏弱")

    payload = {"fetched_at": _now(), "items": items, "meta": meta}
    _save_cache(data_dir, payload)
    return items, meta
