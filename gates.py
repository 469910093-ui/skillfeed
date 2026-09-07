"""Feed 门禁：G_source / G_star / G_rel / G_parse。"""

from __future__ import annotations

import re
from typing import Any, Optional

import rank

DEFAULT_ALLOWED_SOURCES = frozenset({
    "github.com/trending",
    "hellogithub",
    "github-search",
    "catalog",
    "xiaohongshu",
    "corpus",
})

GATE_PROFILES = {
    "loose": {"min_stars": 5, "min_rel": 0.05},
    "standard": {"min_stars": 20, "min_rel": 0.15},
    "strict": {"min_stars": 50, "min_rel": 0.25},
}

# ── description 形态校验 ────────────────────────────────────────────────────
# 判据是「这个值在描述一种能力吗」，不是穷举坏形态——穷举永远漏。所以每条规则
# 都要求「整个值就是一个非能力对象」（单 token 的路径/URL/文件名、纯标点、与
# name 逐字相同），只要值里出现了正常的词句结构就一律放行。
#
# 起因：description = "../../SKILL.md" 长度 14，只看长度的旧规则放它过关。
# 这类值来自 git 符号链接——raw.githubusercontent 把 symlink 的 blob 内容
# （也就是目标路径本身）当正文返回，解析器取首行就拿到一条路径。它会一路流到
# i18n（花一次 LLM 调用翻译一个文件路径）、scene 分类和卡片正文。
#
# 收紧比放宽危险：上一轮放宽救回 81 条优质内容，正说明「被拒的那批平均质量
# 更高」。所以这组规则在 4988 条全量语料（corpus 4210 + feed 383 + 单条快照
# 52 + 本机已装 SKILL.md 343）上实测只命中 1 条，就是上面那个真坏值，0 误伤。
# 特别注意 CJK：中文描述常见「删除图像背景/抠图工具」这种带斜杠又没空格的写法，
# 所以路径判定必须先要求 ASCII（\w 在 Python 正则里是匹配汉字的，早期版本
# 就因此误伤过）。
_WORD_CHAR_RE = re.compile(r"[A-Za-z0-9\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]")
_URLISH_RE = re.compile(r"^(?:https?://|www\.|git@)\S+$", re.I)
_ASCII_PATHISH_RE = re.compile(r"^[A-Za-z0-9._~/\\-]+$")
_FILE_EXT_RE = re.compile(
    r"\.(?:md|markdown|mdx|py|json|ya?ml|toml|txt|ts|tsx|js|jsx|html?|css"
    r"|sh|bash|ps1|rst|ini|cfg)$",
    re.I,
)


def description_shape_reason(desc: str, name: str = "") -> str:
    """description 不像一句能力描述时返回原因名；正常返回空串。

    原因名会原样进被拒明细的 reason 字段，排查时能直接看出是哪条拦的。
    """
    d = (desc or "").strip()
    if not _WORD_CHAR_RE.search(d):
        # 纯标点/纯符号：块标量残留（">"、"|-"）、分隔线、只有 emoji 都在这
        return "shape_no_word_char"
    if not re.search(r"\s", d):
        # 以下三条只对「整个值是一个 token」生效，正常描述必然带空白
        if _URLISH_RE.match(d):
            return "shape_pure_url"
        if d.isascii() and _ASCII_PATHISH_RE.match(d):
            if "/" in d or "\\" in d:
                return "shape_pure_path"
            if _FILE_EXT_RE.search(d):
                return "shape_pure_filename"
    if name and d.casefold() == name.strip().casefold():
        # 描述逐字等于名字：解析器没找到 description，把 name 又抄了一遍
        return "shape_same_as_name"
    return ""


def resolve_thresholds(
    cfg: dict,
    *,
    min_stars: Optional[int] = None,
    min_rel: Optional[float] = None,
) -> tuple[int, float, str]:
    profile = str(cfg.get("gate_profile") or "standard").lower()
    base = dict(GATE_PROFILES.get(profile) or GATE_PROFILES["standard"])
    stars = int(min_stars if min_stars is not None else cfg.get("min_stars", base["min_stars"]))
    rel = float(min_rel if min_rel is not None else cfg.get("min_rel", base["min_rel"]))
    return stars, rel, profile


def run_gates(
    candidates: list[dict],
    *,
    trending_names: set[str],
    min_stars: int,
    min_rel: float,
    interest_toks: set[str],
    allowed_sources: Optional[set[str]] = None,
    star_exempt_sources: Optional[set[str]] = None,
    intent: str = "",
) -> tuple[list[dict], dict]:
    """
    对已探测到的 skill 候选跑门禁。
    返回 (passed, summary)。
    """
    allowed = set(allowed_sources or DEFAULT_ALLOWED_SOURCES)
    star_exempt = set(star_exempt_sources or {"hellogithub", "corpus"})

    query_extra = rank.tokenize(intent, query=True) if intent else set()
    interest = set(interest_toks) | query_extra

    docs = [
        " ".join([
            c.get("name", ""),
            c.get("description", ""),
            c.get("keywords", ""),
            c.get("body_preview", ""),
        ])
        for c in candidates
    ]
    df, n = rank.build_df(docs) if docs else ({}, 1)

    summary: dict[str, Any] = {
        "input": len(candidates),
        "passed": 0,
        "rejected": {
            "G_source": 0,
            "G_star": 0,
            "G_rel": 0,
            "G_parse": 0,
        },
        # G_parse 现在有 7 种拒因（长度 2 种 + 形态 5 种），只看总数分不清是解析器
        # 坏了还是上游内容本身脏。这层计数让漏斗自己说清是哪一类在涨。
        "parse_reasons": {},
        "details": [],
        "allowed_sources": sorted(allowed),
    }
    passed: list[dict] = []

    for c in candidates:
        full_name = c.get("full_name") or ""
        source = c.get("source") or ""

        # G_source：声明源集合；trending 条目还需在本轮榜单内
        if source not in allowed:
            summary["rejected"]["G_source"] += 1
            summary["details"].append({"repo": full_name, "gate": "G_source", "ok": False, "source": source})
            continue
        if source == "github.com/trending" and full_name not in trending_names:
            summary["rejected"]["G_source"] += 1
            summary["details"].append({"repo": full_name, "gate": "G_source", "ok": False, "source": source})
            continue

        # G_star（策展源可豁免未知星数）
        stars_raw = c.get("stars")
        if source in star_exempt and stars_raw is None:
            stars = -1  # exempt
        else:
            stars = int(stars_raw or 0)
            if stars < min_stars:
                summary["rejected"]["G_star"] += 1
                summary["details"].append({
                    "repo": full_name, "gate": "G_star", "ok": False,
                    "stars": stars, "min_stars": min_stars,
                })
                continue

        # G_parse
        name = (c.get("name") or "").strip()
        desc = (c.get("description") or "").strip()
        parse_reason = ""
        if len(name) < 1:
            parse_reason = "empty_name"
        elif len(desc) < 10:
            parse_reason = "short_description"
        else:
            # 长度过了不代表是描述："../../SKILL.md" 长 14 照样能混过去
            parse_reason = description_shape_reason(desc, name)
        if parse_reason:
            summary["rejected"]["G_parse"] += 1
            summary["parse_reasons"][parse_reason] = (
                summary["parse_reasons"].get(parse_reason, 0) + 1
            )
            # 只记一个计数的话，下次解析器出问题（比如 YAML 块标量被当成 ">"）
            # 从漏斗上完全看不出来，得重跑 36 分钟的 refresh 才能定位。
            # 这里落下 skill_path 和被拒时的实际取值，供离线复盘。
            summary["details"].append({
                "repo": full_name, "gate": "G_parse", "ok": False,
                "source": source,
                "skill_path": c.get("skill_path") or "",
                "reason": parse_reason,
                "name": name[:60],
                "description": desc[:60],
            })
            continue

        # G_rel
        score, why = rank.relevance_score(c, interest, df, n)
        if score < min_rel:
            summary["rejected"]["G_rel"] += 1
            summary["details"].append({
                "repo": full_name, "gate": "G_rel", "ok": False,
                "score": score, "min_rel": min_rel, "why": why,
            })
            continue

        item = dict(c)
        item["rel_score"] = score
        item["rel_why"] = why
        if stars >= 0:
            item["stars"] = stars
        item["gates"] = {
            "G_source": "PASS",
            "G_star": "PASS" if stars >= 0 else "SKIP",
            "G_rel": "PASS",
            "G_parse": "PASS",
        }
        passed.append(item)
        summary["details"].append({
            "repo": full_name, "gate": "ALL", "ok": True, "score": score, "source": source,
        })

    passed.sort(key=lambda x: (-float(x.get("rel_score") or 0), -int(x.get("stars") or 0)))
    summary["passed"] = len(passed)
    return passed, summary
