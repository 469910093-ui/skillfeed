"""小红书源：媒讯助手导出 / Chrome 采集 → 抽取 GitHub skill 仓。

数据落盘：~/.skill-feed/xhs/mentions.json
候选行 source=xiaohongshu，供 refresh 探测 SKILL.md。
"""

from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import hellogithub

SOURCE = "xiaohongshu"

# 近一周中文社区高频安利的 skill 仓（网络检索 + 小红书话题交叉验证的种子）
# crawl 成功后会与笔记里抽出的链接合并；种子保证空采集时仍有 XHS 信号
HOT_SKILL_SEEDS = [
    {
        "full_name": "comeonzhj/Auto-Redbook-Skills",
        "note_title": "自动写小红书笔记+配图+发布的 Skills",
        "keyword": "Claude Skills 小红书",
    },
    {
        "full_name": "mythkiven/rednote-director-skill",
        "note_title": "小红书图文视觉导演 Skill",
        "keyword": "rednote director skill",
    },
    {
        "full_name": "deepvector-ai/redbook-director-skill",
        "note_title": "Redbook Director Skill 轮播规划",
        "keyword": "小红书 Skill",
    },
    {
        "full_name": "vivy-yi/xiaohongshu-skills",
        "note_title": "139 个小红书运营 Claude Skills",
        "keyword": "小红书运营 skills",
    },
    {
        "full_name": "hardikpandya/stop-slop",
        "note_title": "去 AI 味 writing skill",
        "keyword": "Claude Skill 去AI味",
    },
    {
        "full_name": "JuliusBrussee/caveman",
        "note_title": "Caveman skill 热议",
        "keyword": "Claude Code Skills",
    },
    {
        "full_name": "obra/superpowers",
        "note_title": "superpowers skill 套件",
        "keyword": "Cursor Skills",
    },
    {
        "full_name": "anthropics/skills",
        "note_title": "Anthropic 官方 Agent Skills",
        "keyword": "SKILL.md",
    },
    {
        "full_name": "vercel-labs/agent-skills",
        "note_title": "Vercel agent skills / skills.sh",
        "keyword": "skills.sh",
    },
    {
        "full_name": "heygen-com/hyperframes",
        "note_title": "Hyperframes 视频 skill",
        "keyword": "Claude Skills 视频",
    },
    {
        "full_name": "Nutlope/hallmark",
        "note_title": "Hallmark skill",
        "keyword": "Cursor agent skill",
    },
    {
        "full_name": "bradautomates/claude-video",
        "note_title": "Claude video skill",
        "keyword": "Claude Code skill",
    },
    {
        "full_name": "alchaincyf/nuwa-skill",
        "note_title": "花叔「女娲.skill」小红书热推（GitHub 3万+星）",
        "keyword": "女娲 skill",
    },
    {
        "full_name": "alchaincyf/huashu-design",
        "note_title": "花叔设计/内容 skill",
        "keyword": "花叔 skill",
    },
    {
        "full_name": "alchaincyf/zhangxuefeng-skill",
        "note_title": "张雪峰.skill 小红书话题",
        "keyword": "张雪峰 skill",
    },
    {
        "full_name": "tmstack/awesome-persona-skills",
        "note_title": "人格/角色 skill 合集被刷屏",
        "keyword": "persona skill",
    },
    {
        "full_name": "VoltAgent/awesome-agent-skills",
        "note_title": "1000+ agent skills 合集被安利",
        "keyword": "awesome agent skills",
    },
    {
        "full_name": "ComposioHQ/awesome-claude-skills",
        "note_title": "awesome claude skills 清单",
        "keyword": "Claude Skills 合集",
    },
    {
        "full_name": "travisvn/awesome-claude-skills",
        "note_title": "Claude Skills 资源列表",
        "keyword": "Claude Skills GitHub",
    },
    {
        "full_name": "addyosmani/agent-skills",
        "note_title": "Addy Osmani agent-skills",
        "keyword": "agent skills",
    },
]


def xhs_dir(data_dir: Path) -> Path:
    return data_dir / "xhs"


def mentions_path(data_dir: Path) -> Path:
    return xhs_dir(data_dir) / "mentions.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_GH_RE = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.I,
)


def extract_repos_from_text(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in _GH_RE.finditer(text or ""):
        owner, repo = m.group(1), m.group(2)
        if owner.lower() in {"topics", "settings", "orgs", "marketplace", "sponsors"}:
            continue
        if repo.lower() in {"blob", "tree", "issues", "pull", "releases", "wiki", "actions"}:
            continue
        fn = f"{owner}/{repo}"
        key = fn.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(fn)
    # 裸写 owner/repo（排除 github.com/... 已匹配段）
    blob = (text or "").lower()
    if any(k in blob for k in ("skill", "claude", "cursor", "codex", "agent")):
        for m in re.finditer(r"(?<![A-Za-z0-9_.-])([A-Za-z0-9][A-Za-z0-9_.-]{1,39})/([A-Za-z0-9_.-]{2,80})(?![A-Za-z0-9_.-])", text or ""):
            owner, repo = m.group(1), m.group(2)
            if owner.lower() in {"http", "https", "www", "github", "com"}:
                continue
            if "." in owner:  # 避免 github.com
                continue
            if repo.lower() in {"blob", "tree", "issues", "pull"}:
                continue
            if re.search(r"[\u4e00-\u9fff]", f"{owner}/{repo}"):
                continue
            fn = f"{owner}/{repo}"
            key = fn.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(fn)
    return out


def load_mentions(data_dir: Path) -> dict:
    path = mentions_path(data_dir)
    if not path.exists():
        return {"updated_at": "", "notes": [], "repos": []}
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, OSError):
        pass
    return {"updated_at": "", "notes": [], "repos": []}


def save_mentions(data_dir: Path, payload: dict) -> Path:
    d = xhs_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = mentions_path(data_dir)
    payload = dict(payload)
    payload["updated_at"] = _now()
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def ingest_export_csv(data_dir: Path, csv_path: Path) -> dict:
    """导入媒讯助手导出的 CSV（任意含 title/desc/content/url 列）。"""
    notes: list[dict] = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            title = (row.get("title") or row.get("标题") or row.get("note_title") or "").strip()
            desc = (
                row.get("desc")
                or row.get("description")
                or row.get("内容")
                or row.get("content")
                or row.get("正文")
                or ""
            ).strip()
            url = (row.get("url") or row.get("链接") or row.get("note_url") or "").strip()
            likes = row.get("likes") or row.get("点赞数") or row.get("liked_count") or 0
            try:
                likes_n = int(str(likes).replace(",", "") or 0)
            except ValueError:
                likes_n = 0
            text = f"{title}\n{desc}\n{url}"
            repos = extract_repos_from_text(text)
            notes.append({
                "title": title,
                "desc": desc[:800],
                "url": url,
                "likes": likes_n,
                "repos": repos,
                "source_file": str(csv_path),
            })
    prev = load_mentions(data_dir)
    merged_notes = list(prev.get("notes") or []) + notes
    repos_map: dict[str, dict] = {}
    for n in merged_notes:
        for fn in n.get("repos") or []:
            cur = repos_map.get(fn.lower())
            if not cur or int(n.get("likes") or 0) > int(cur.get("likes") or 0):
                repos_map[fn.lower()] = {
                    "full_name": fn,
                    "likes": int(n.get("likes") or 0),
                    "note_title": n.get("title") or "",
                    "note_url": n.get("url") or "",
                }
    payload = {
        "notes": merged_notes[-500:],
        "repos": list(repos_map.values()),
        "import": {"csv": str(csv_path), "added_notes": len(notes)},
    }
    save_mentions(data_dir, payload)
    return payload


def ensure_seed_mentions(data_dir: Path) -> dict:
    """保证至少有一波近一周热议种子；不覆盖已有更高赞笔记。"""
    prev = load_mentions(data_dir)
    repos_map: dict[str, dict] = {}
    for r in prev.get("repos") or []:
        fn = (r.get("full_name") or "").strip()
        if fn:
            repos_map[fn.lower()] = dict(r)
    for seed in HOT_SKILL_SEEDS:
        fn = seed["full_name"]
        key = fn.lower()
        if key not in repos_map:
            repos_map[key] = {
                "full_name": fn,
                "likes": 0,
                "note_title": seed["note_title"],
                "note_url": "",
                "keyword": seed["keyword"],
                "seed": True,
            }
    notes = list(prev.get("notes") or [])
    payload = {
        "notes": notes,
        "repos": list(repos_map.values()),
        "seeded": True,
    }
    save_mentions(data_dir, payload)
    return payload


def merge_crawl_notes(data_dir: Path, notes: list[dict]) -> dict:
    prev = load_mentions(data_dir)
    merged = list(prev.get("notes") or [])
    for n in notes:
        title = (n.get("title") or "").strip()
        desc = (n.get("desc") or n.get("description") or "").strip()
        url = (n.get("url") or "").strip()
        likes = int(n.get("likes") or n.get("liked_count") or 0)
        text = f"{title}\n{desc}\n{url}\n{n.get('author') or ''}"
        repos = list(n.get("repos") or []) or extract_repos_from_text(text)
        merged.append({
            "title": title,
            "desc": desc[:800],
            "url": url,
            "likes": likes,
            "author": n.get("author") or "",
            "keyword": n.get("keyword") or "",
            "repos": repos,
            "crawled_at": _now(),
        })
    repos_map: dict[str, dict] = {}
    for r in prev.get("repos") or []:
        fn = (r.get("full_name") or "").strip()
        if fn:
            repos_map[fn.lower()] = dict(r)
    for n in merged:
        for fn in n.get("repos") or []:
            key = fn.lower()
            cur = repos_map.get(key)
            if not cur or int(n.get("likes") or 0) > int(cur.get("likes") or 0):
                repos_map[key] = {
                    "full_name": fn,
                    "likes": int(n.get("likes") or 0),
                    "note_title": n.get("title") or "",
                    "note_url": n.get("url") or "",
                    "keyword": n.get("keyword") or "",
                }
    # 保留种子
    for seed in HOT_SKILL_SEEDS:
        key = seed["full_name"].lower()
        if key not in repos_map:
            repos_map[key] = {
                "full_name": seed["full_name"],
                "likes": 0,
                "note_title": seed["note_title"],
                "note_url": "",
                "keyword": seed["keyword"],
                "seed": True,
            }
    payload = {
        "notes": merged[-500:],
        "repos": sorted(repos_map.values(), key=lambda x: int(x.get("likes") or 0), reverse=True),
        "crawl": {"notes": len(notes)},
    }
    save_mentions(data_dir, payload)
    return payload


def candidates_from_mentions(data_dir: Path, *, max_repos: int = 40) -> tuple[list[dict], dict]:
    ensure_seed_mentions(data_dir)
    data = load_mentions(data_dir)
    rows: list[dict] = []
    seen: set[str] = set()
    repos = sorted(
        data.get("repos") or [],
        key=lambda x: (0 if x.get("seed") else 1, -int(x.get("likes") or 0)),
    )
    for r in repos:
        fn = (r.get("full_name") or "").strip()
        if not fn or "/" not in fn:
            continue
        # 规范化
        gurl = hellogithub.unwrap_github_url(f"https://github.com/{fn}")
        fn2 = hellogithub.full_name_from_url(gurl) or fn
        key = fn2.lower()
        if key in seen:
            continue
        seen.add(key)
        title = (r.get("note_title") or "").strip()
        desc = title or f"小红书热议 skill：{fn2}"
        if len(desc) < 10:
            desc = f"Xiaohongshu mentioned agent skill {fn2}"
        rows.append({
            "full_name": fn2,
            "url": f"https://github.com/{fn2}",
            "description": desc[:280],
            "language": "",
            "stars": None,
            "stars_today": 0,
            "source": SOURCE,
            "kind": "skill",
            "xhs_likes": int(r.get("likes") or 0),
            "xhs_note_url": r.get("note_url") or "",
            "xhs_keyword": r.get("keyword") or "",
        })
        if len(rows) >= max_repos:
            break
    meta = {
        "source": SOURCE,
        "mentions_updated_at": data.get("updated_at"),
        "note_count": len(data.get("notes") or []),
        "repo_count": len(data.get("repos") or []),
        "returned": len(rows),
    }
    return rows, meta
