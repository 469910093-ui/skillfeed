"""从 SKILL.md / 描述提炼「解决什么问题」+ 亮点要点（卡片一屏可读）。"""

from __future__ import annotations

import re
from typing import Any


_SKIP_HEAD = re.compile(
    r"^(anti-pattern|hard-gate|note|notes|license|安装|install|usage|when to use)\b",
    re.I,
)
_BULLET = re.compile(r"^\s*(?:[-*]|\d+\.)\s+(.+)$")
_HEADING = re.compile(r"^\s{0,3}#{1,3}\s+(.+)$")


def _clean_line(s: str) -> str:
    s = re.sub(r"[`*_~]+", "", s or "")
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _is_useful(s: str) -> bool:
    if len(s) < 8 or len(s) > 120:
        return False
    low = s.lower()
    if low.startswith("http") or s.startswith("<"):
        return False
    if _SKIP_HEAD.search(s):
        return False
    return True


def extract_highlights(
    body: str = "",
    description: str = "",
    *,
    max_n: int = 4,
) -> dict[str, Any]:
    """
    返回:
      problem: 一句话问题/价值
      highlights: 3~4 条短亮点
    """
    desc = _clean_line(description)
    body = body or ""

    bullets: list[str] = []
    headings: list[str] = []
    paras: list[str] = []

    for raw in body.splitlines():
        line = raw.strip()
        if not line or line == "---" or line.startswith("```"):
            continue
        hm = _HEADING.match(line)
        if hm:
            h = _clean_line(hm.group(1))
            if _is_useful(h) and not _SKIP_HEAD.search(h):
                headings.append(h)
            continue
        bm = _BULLET.match(line)
        if bm:
            b = _clean_line(bm.group(1))
            if _is_useful(b):
                bullets.append(b)
            continue
        if line.startswith("#") or line.startswith("<"):
            continue
        p = _clean_line(line)
        if _is_useful(p):
            paras.append(p)

    problem = desc
    if not problem and paras:
        problem = paras[0]
    if not problem and headings:
        problem = headings[0]
    if len(problem) > 110:
        problem = problem[:109] + "…"

    highlights: list[str] = []
    seen: set[str] = set()

    def push(s: str) -> None:
        key = s.lower()
        if not s or key in seen:
            return
        if problem and key == problem.lower():
            return
        seen.add(key)
        highlights.append(s)

    for b in bullets:
        push(b)
        if len(highlights) >= max_n:
            break
    if len(highlights) < max_n:
        for h in headings:
            push(h)
            if len(highlights) >= max_n:
                break
    if len(highlights) < 2:
        for p in paras[1:]:
            push(p)
            if len(highlights) >= max_n:
                break
    if not highlights and problem:
        # 从问题句拆不出要点时，给可读占位
        highlights = ["打开 GitHub 查看完整 SKILL.md 与用法"]

    return {
        "problem": problem,
        "highlights": highlights[:max_n],
    }
