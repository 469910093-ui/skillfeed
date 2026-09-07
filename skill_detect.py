"""探测仓库内 SKILL.md 并抽取元数据。"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
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

# monorepo 内优先展开的设计/视觉 skill 目录名片段（越靠前越优先）
PRIORITY_SKILL_DIRS = (
    "frontend-design",
    "web-design-guidelines",
    "web-design",
    "canvas-design",
    "brand-guidelines",
    "theme-factory",
    "ui-ux-pro-max",
    "shadcn-ui",
    "shadcn",
    "figma-implement-design",
    "figma-design-to-code",
    "figma-generate-design",
    "figma-use",
    "figma",
    "prototype",
    "taste-skill",
    "taste",
    "design-system",
    "ui-design",
    "product-design",
    "open-design",
    "hallmark",
)

# 单仓最多展开多少条独立 feed 卡片（优先 PRIORITY）
DEFAULT_EXPAND_LIMIT = 6
FIND_PATHS_CAP = 24
# 一层扫空后允许再下钻的父目录个数上限，防止分类式仓库把 API 配额打爆
DESCEND_CAP = 12


def path_priority(path: str) -> int:
    p = (path or "").lower()
    for i, key in enumerate(PRIORITY_SKILL_DIRS):
        if key in p:
            return i
    return 10_000


def skill_item_id(full_name: str, skill_path: str = "") -> str:
    fn = (full_name or "").strip()
    sp = (skill_path or "SKILL.md").strip().lstrip("/")
    return f"{fn}::{sp}"


def _dir_name_from_path(path: str, fallback: str) -> str:
    parts = (path or "").rstrip("/").split("/")
    if len(parts) >= 2 and parts[-1].lower() == "skill.md":
        return parts[-2]
    return fallback


def looks_like_skill_repo(description: str, full_name: str = "") -> bool:
    hay = f"{full_name} {description}".lower()
    return any(h in hay for h in SKILL_HINTS)


_FM_KEY_RE = re.compile(r"^([A-Za-z0-9_-]+):\s*(.*)$")
# YAML 块标量指示符：| > 可带 chomping(+/-) 和缩进数字，如 |、>-、|2-
_BLOCK_SCALAR_RE = re.compile(r"^[|>]\d*[+-]?$|^[|>][+-]?\d*$")


def _fold(lines: list[str]) -> str:
    """把多行折成一行：卡片只展示一行描述，literal(|) 和 folded(>) 一律压平。"""
    return re.sub(r"\s+", " ", " ".join(x.strip() for x in lines)).strip()


def parse_frontmatter(block: str) -> dict[str, str]:
    """解析 SKILL.md 的 YAML frontmatter（只认顶层标量，够用即可）。

    必须支持块标量：真实语料里 `description: |` / `>` / `>-` 是主流写法
    （481/754 个 SKILL.md 用它），一行一行读会把 ">" 本身当成描述，
    长度 1 直接被 G_parse 拒掉。
    顶层 key 后面缩进的行才是续行；空值（嵌套 map / 列表）保持空串，
    否则 `tags:` 下面的 `- foo` 会被拼成假描述。
    """
    fm: dict[str, str] = {}
    lines = block.splitlines()
    i = 0
    while i < len(lines):
        m = _FM_KEY_RE.match(lines[i])
        if not m:
            i += 1
            continue
        key = m.group(1).strip().lower()
        raw = m.group(2).strip()
        i += 1
        if not raw:
            fm[key] = ""
            continue
        block_scalar = bool(_BLOCK_SCALAR_RE.match(raw))
        buf: list[str] = [] if block_scalar else [raw]
        while i < len(lines):
            nxt = lines[i]
            if nxt.strip() and not nxt.startswith((" ", "\t")):
                break
            if not nxt.strip() and not block_scalar:
                break  # plain 多行标量遇空行即结束；块标量里的空行属于内容
            buf.append(nxt)
            i += 1
        fm[key] = _fold(buf) if block_scalar else _fold(buf).strip("\"'")
    return fm


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
            block = body[3:end].strip("\n")
            body = body[end + 4:].lstrip("\n")
            fm = parse_frontmatter(block)
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


def _http_get(
    url: str, user_agent: str, timeout: int = 20, token: str = "",
) -> tuple[int, str]:
    headers = {
        "User-Agent": user_agent,
        "Accept": "application/vnd.github+json, text/plain, */*",
    }
    # api.github.com 匿名访问会直接 403（不是限流，是拒绝），monorepo 展开必须带 token
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
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
    except UnicodeEncodeError:
        # 兜底：URL 里漏了没编码的非 ASCII 字符时，urllib 会抛这个而不是 URLError。
        # 不接住的话一条中文路径就能让整个仓库的探测崩掉。
        return 0, ""


def _enc_path(path: str) -> str:
    """给仓库内路径做百分号编码，保留分隔符。

    中文目录名的 skill（如 xiaohongshu-skills 里的中文子目录）如果直接拼进 URL，
    urllib 会抛 UnicodeEncodeError，整个仓库被跳过——正好丢掉中文内容类供给。
    """
    return urllib.parse.quote(path, safe="/")


def fetch_raw_skill(
    owner: str, repo: str, path: str, user_agent: str, token: str = "",
) -> Optional[str]:
    # 优先 raw HEAD，失败再试 main/master
    for ref in ("HEAD", "main", "master"):
        url = (
            f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/"
            f"{_enc_path(path)}"
        )
        code, text = _http_get(url, user_agent, token=token)
        if code == 200 and text.strip():
            return text
    return None


def list_dir_api(
    owner: str, repo: str, path: str, user_agent: str, token: str = "",
) -> list[dict]:
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/"
        f"{_enc_path(path)}"
    )
    code, text = _http_get(url, user_agent, token=token)
    if code != 200:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def find_skill_paths(
    owner: str, repo: str, user_agent: str, token: str = "",
) -> list[str]:
    """返回仓库内 SKILL.md 相对路径列表（有限探测，避免全树遍历）。"""
    found: list[str] = []
    for p in CANDIDATE_PATHS:
        if fetch_raw_skill(owner, repo, p, user_agent, token) is not None:
            found.append(p)

    # 常见 skills 目录下一层
    descend_budget = DESCEND_CAP
    for base in ("skills", ".cursor/skills", ".claude/skills", ".agents/skills", ".codex/skills"):
        entries = list_dir_api(owner, repo, base, user_agent, token)
        for ent in entries:
            if ent.get("type") != "dir":
                continue
            name = ent.get("name") or ""
            rel = f"{base}/{name}/SKILL.md"
            if rel in found:
                continue
            if fetch_raw_skill(owner, repo, rel, user_agent, token) is not None:
                found.append(rel)
            elif descend_budget > 0:
                # 分类式 monorepo：skills/<分类>/<skill>/SKILL.md。第一层是分类目录
                # （常见中文命名，如 skills/01-内容创作/），本身没有 SKILL.md，
                # 只扫一层会整仓归零。限量再下钻一层。
                descend_budget -= 1
                for sub in list_dir_api(owner, repo, f"{base}/{name}", user_agent, token):
                    if sub.get("type") != "dir":
                        continue
                    rel2 = f"{base}/{name}/{sub.get('name') or ''}/SKILL.md"
                    if rel2 in found:
                        continue
                    if fetch_raw_skill(owner, repo, rel2, user_agent, token) is not None:
                        found.append(rel2)
                    if len(found) >= FIND_PATHS_CAP:
                        break
            if len(found) >= FIND_PATHS_CAP:
                break
        if len(found) >= FIND_PATHS_CAP:
            break
    found.sort(key=path_priority)
    return found


def _build_skill_item(repo: dict, path: str, text: str, all_paths: list[str]) -> dict:
    full_name = repo["full_name"]
    owner, name = full_name.split("/", 1)
    desc = repo.get("description") or ""
    meta = parse_skill_md(text)
    if not meta["name"]:
        meta["name"] = _dir_name_from_path(path, name)
    dir_name = meta["name"] or name
    dir_name = re.sub(r"[^A-Za-z0-9._-]+", "-", dir_name).strip("-").lower() or name.lower()
    out = dict(repo)
    out.update({
        "id": skill_item_id(full_name, path),
        "skill_path": path,
        "skill_paths": all_paths,
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


def enrich_repo(
    repo: dict, user_agent: str, always_probe: bool = False, token: str = "",
) -> Optional[dict]:
    """
    对 trending 条目探测 skill。返回增强 dict，或 None（非 skill）。
    repo 需含 full_name / description / stars 等。
    多 skill 仓优先选 PRIORITY（如 frontend-design），不再盲目取 paths[0]。
    """
    items = enrich_repo_multi(
        repo, user_agent, always_probe=always_probe, max_skills=1, token=token,
    )
    return items[0] if items else None


def enrich_repo_multi(
    repo: dict,
    user_agent: str,
    always_probe: bool = False,
    max_skills: int = DEFAULT_EXPAND_LIMIT,
    token: str = "",
) -> list[dict]:
    """探测并展开 monorepo：优先产出设计类子 skill 多张卡片。"""
    full_name = repo["full_name"]
    owner, name = full_name.split("/", 1)
    desc = repo.get("description") or ""
    hint = looks_like_skill_repo(desc, full_name)
    if not always_probe and not hint:
        root = fetch_raw_skill(owner, name, "SKILL.md", user_agent, token)
        if root is None:
            return []
        return [_build_skill_item(repo, "SKILL.md", root, ["SKILL.md"])]

    paths = find_skill_paths(owner, name, user_agent, token)
    if not paths:
        return []

    # 优先队列：PRIORITY 命中全部纳入，再补其余，直到 max_skills
    priority = [p for p in paths if path_priority(p) < 10_000]
    rest = [p for p in paths if p not in priority]
    # 若根 SKILL.md 只是索引、且已有子 skill，跳过根以免挤掉设计卡
    if len(paths) > 1 and "SKILL.md" in rest and any("/" in p for p in priority + rest):
        rest = [p for p in rest if p != "SKILL.md"]
    chosen = (priority + rest)[: max(1, int(max_skills))]

    out: list[dict] = []
    for path in chosen:
        text = fetch_raw_skill(owner, name, path, user_agent, token) or ""
        if not text.strip():
            continue
        out.append(_build_skill_item(repo, path, text, paths))
    return out
