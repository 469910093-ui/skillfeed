"""探测仓库内 SKILL.md 并抽取元数据。"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Optional

SKILL_HINTS = (
    "skill.md", "claude skill", "cursor skill", "agent skill", "agent skills",
    "codex skill", "openclaw skill", "skills/", ".cursor/skills",
)

CANDIDATE_PATHS = [
    "SKILL.md",
    "skills/SKILL.md",
    ".cursor/skills/SKILL.md",
    ".claude/skills/SKILL.md",
    ".agents/skills/SKILL.md",
]


def looks_like_skill_repo(description: str, full_name: str = "") -> bool:
    hay = f"{full_name} {description}".lower()
    return any(h in hay for h in SKILL_HINTS)


def parse_skill_md(text: str) -> dict:
    """解析 frontmatter + 描述。"""
    name = ""
    description = ""
    keywords = ""
    body = text or ""
    fm: dict[str, str] = {}
    if body.startswith("---"):
        end = body.find("\n---", 3)
        if end != -1:
            block = body[3:end].strip()
            body = body[end + 4:].lstrip("\n")
            for line in block.splitlines():
                m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
                if not m:
                    continue
                key, val = m.group(1).strip().lower(), m.group(2).strip().strip("\"'")
                fm[key] = val
    name = fm.get("name") or ""
    description = fm.get("description") or ""
    keywords = fm.get("keywords") or fm.get("tags") or ""
    if not description:
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("```"):
                continue
            description = line
            break
    if not name:
        # 从首个一级标题兜底
        m = re.search(r"^#\s+(.+)$", body, re.M)
        if m:
            name = m.group(1).strip()
    return {
        "name": name,
        "description": description,
        "keywords": keywords,
        "body_preview": body[:800],
        "frontmatter": fm,
    }


def _http_get(url: str, user_agent: str, timeout: int = 20) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "application/vnd.github+json, text/plain, */*",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.status, raw.decode(charset, errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, ""


def fetch_raw_skill(owner: str, repo: str, path: str, user_agent: str) -> Optional[str]:
    # 优先 raw HEAD，失败再试 main/master
    for ref in ("HEAD", "main", "master"):
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
        code, text = _http_get(url, user_agent)
        if code == 200 and text.strip():
            return text
    return None


def list_dir_api(owner: str, repo: str, path: str, user_agent: str) -> list[dict]:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    code, text = _http_get(url, user_agent)
    if code != 200:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def find_skill_paths(owner: str, repo: str, user_agent: str) -> list[str]:
    """返回仓库内 SKILL.md 相对路径列表（有限探测，避免全树遍历）。"""
    found: list[str] = []
    for p in CANDIDATE_PATHS:
        if fetch_raw_skill(owner, repo, p, user_agent) is not None:
            found.append(p)

    # 常见 skills 目录下一层
    for base in ("skills", ".cursor/skills", ".claude/skills", ".agents/skills", ".codex/skills"):
        entries = list_dir_api(owner, repo, base, user_agent)
        for ent in entries:
            if ent.get("type") != "dir":
                continue
            name = ent.get("name") or ""
            rel = f"{base}/{name}/SKILL.md"
            if rel in found:
                continue
            if fetch_raw_skill(owner, repo, rel, user_agent) is not None:
                found.append(rel)
            if len(found) >= 8:
                return found
    return found


def enrich_repo(repo: dict, user_agent: str, always_probe: bool = False) -> Optional[dict]:
    """
    对 trending 条目探测 skill。返回增强 dict，或 None（非 skill）。
    repo 需含 full_name / description / stars 等。
    """
    full_name = repo["full_name"]
    owner, name = full_name.split("/", 1)
    desc = repo.get("description") or ""
    hint = looks_like_skill_repo(desc, full_name)
    if not always_probe and not hint:
        # 轻量：先探根 SKILL.md，避免对全部 trending 打爆 API
        root = fetch_raw_skill(owner, name, "SKILL.md", user_agent)
        if root is None:
            return None
        paths = ["SKILL.md"]
        text = root
    else:
        paths = find_skill_paths(owner, name, user_agent)
        if not paths:
            return None
        text = fetch_raw_skill(owner, name, paths[0], user_agent) or ""

    meta = parse_skill_md(text)
    if not meta["name"]:
        meta["name"] = paths[0].rstrip("/").split("/")[-2] if "/" in paths[0] else name
    dir_name = meta["name"] or name
    # 规范化目录名
    dir_name = re.sub(r"[^A-Za-z0-9._-]+", "-", dir_name).strip("-").lower() or name.lower()

    out = dict(repo)
    out.update({
        "skill_path": paths[0],
        "skill_paths": paths,
        "name": meta["name"] or dir_name,
        "dir_name": dir_name,
        "description": meta["description"] or desc,
        "keywords": meta["keywords"],
        "body_preview": meta["body_preview"],
        "frontmatter": meta.get("frontmatter") or {},
        "repo_description": desc,
        "kind": repo.get("kind") or "skill",
    })
    return out
