"""从本机 HelloGitHub 镜像解析条目（不依赖 Node digest）。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

DEFAULT_HG_REPO = Path.home() / ".hellogithub" / "HelloGitHub"
CONTENT_SUB = "content"


def resolve_repo(path: Optional[str] = None) -> Path:
    if path:
        return Path(path).expanduser()
    return DEFAULT_HG_REPO


def list_issue_files(repo: Path) -> list[tuple[int, Path]]:
    content = repo / CONTENT_SUB
    if not content.is_dir():
        return []
    out: list[tuple[int, Path]] = []
    for p in content.glob("HelloGitHub*.md"):
        m = re.search(r"(\d+)", p.stem)
        if not m:
            continue
        # 跳过 content/en
        if "en" in p.parts:
            continue
        out.append((int(m.group(1)), p))
    out.sort(key=lambda x: x[0], reverse=True)
    return out


def unwrap_github_url(href: str) -> str:
    try:
        u = urlparse(href)
        qs = parse_qs(u.query)
        target = (qs.get("target") or [None])[0]
        if target and "github.com" in target:
            return target.split("?")[0].rstrip("/")
        if "github.com" in href:
            return href.split("?")[0].rstrip("/")
        return (target or href).split("?")[0].rstrip("/")
    except Exception:  # noqa: BLE001
        return href


def full_name_from_url(url: str) -> str:
    m = re.search(r"github\.com/([^/]+)/([^/#?]+)", url or "", re.I)
    if not m:
        return ""
    return f"{m.group(1)}/{m.group(2)}"


def parse_issue_md(text: str, issue: int) -> list[dict]:
    items: list[dict] = []
    section = "未分类"
    for line in (text or "").splitlines():
        sec = re.match(r"^###\s+(.+?)\s*$", line)
        if sec:
            section = re.sub(r"\s+", " ", sec.group(1)).strip()
            continue
        m = re.match(r"^(\d+)、\[([^\]]+)\]\(([^)]+)\)\s*[：:]\s*(.+)$", line)
        if not m:
            continue
        idx, name, href, desc_raw = m.group(1), m.group(2), m.group(3), m.group(4)
        desc = re.sub(r"来自\s*\[[^\]]+\]\([^)]+\)\s*的分享", "", desc_raw)
        desc = re.sub(r"<[^>]+>", "", desc).strip()
        gurl = unwrap_github_url(href)
        fn = full_name_from_url(gurl)
        if not fn:
            continue
        items.append({
            "index": int(idx),
            "name": name,
            "hg_section": section,
            "description": desc,
            "url": gurl,
            "full_name": fn,
            "issue": issue,
            "source": "hellogithub",
            "hellogithub_url": href if href.startswith("http") else f"https://hellogithub.com{href}",
        })
    return items


def load_items(
    repo: Optional[Path] = None,
    *,
    max_issues: int = 0,
    sections: Optional[set[str]] = None,
) -> list[dict]:
    """
    加载月刊条目。
    max_issues=0 表示全部；sections 为 None 表示全部栏目。
    """
    root = repo or resolve_repo()
    files = list_issue_files(root)
    if max_issues and max_issues > 0:
        files = files[:max_issues]
    out: list[dict] = []
    for issue, path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for it in parse_issue_md(text, issue):
            if sections is not None and it.get("hg_section") not in sections:
                continue
            it["issue_file"] = str(path)
            out.append(it)
    return out


def skill_candidates(repo: Optional[Path] = None, *, max_issues: int = 12) -> list[dict]:
    """Skills 专栏 + 近期人工智能栏目（供 Feed 探测）。"""
    root = repo or resolve_repo()
    # 全历史 Skills + 近 N 期 AI
    skills = load_items(root, max_issues=0, sections={"Skills"})
    ai = load_items(root, max_issues=max_issues, sections={"人工智能"})
    # Skills 优先，按期号新→旧
    seen: set[str] = set()
    merged: list[dict] = []
    for it in sorted(skills + ai, key=lambda x: (-int(x.get("issue") or 0), x.get("full_name") or "")):
        fn = it["full_name"]
        if fn in seen:
            continue
        seen.add(fn)
        kind = "skill" if it.get("hg_section") == "Skills" else "ai-candidate"
        row = dict(it)
        row["kind"] = kind
        row["language"] = ""
        row["stars"] = None  # 未知，门禁可豁免
        row["stars_today"] = 0
        merged.append(row)
    return merged
