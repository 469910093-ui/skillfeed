"""兴趣画像 + 关联打分 + 个性化重排。"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any, Optional

# agent-skill 域词表：无本机 catalog 时的退化查询侧
DOMAIN_TOKENS = {
    "skill", "skills", "agent", "agents", "claude", "cursor", "codex",
    "openclaw", "mcp", "prompt", "workflow", "automation", "llm",
    "技能", "代理", "助手", "工作流", "自动化",
}


def _is_cjk(ch: str) -> bool:
    return "\u4e00" <= ch <= "\u9fff"


def norm(s: str) -> str:
    s = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", " ", (s or "").lower())
    return re.sub(r"\s+", " ", s).strip()


def tokenize(s: str, query: bool = False) -> set[str]:
    toks: set[str] = set()
    for word in norm(s).split(" "):
        if not word:
            continue
        if re.fullmatch(r"[a-z0-9]+", word):
            toks.add(word)
            continue
        chars = list(word)
        i = 0
        while i < len(chars):
            if _is_cjk(chars[i]):
                if not query:
                    toks.add(chars[i])
                if i + 1 < len(chars) and _is_cjk(chars[i + 1]):
                    toks.add(chars[i] + chars[i + 1])
                i += 1
            else:
                j = i
                while j < len(chars) and not _is_cjk(chars[j]):
                    j += 1
                toks.add("".join(chars[i:j]))
                i = j
        if query and len(word) >= 2:
            toks.add(word)
    if query:
        toks = {t for t in toks if len(t) >= 2}
    return toks


def load_interest_tokens(catalog_path: Optional[Path]) -> set[str]:
    """从 skill-picker catalog 聚兴趣 token；缺失则用域词表。"""
    tokens = set(DOMAIN_TOKENS)
    if not catalog_path:
        return tokens
    path = Path(catalog_path).expanduser()
    if not path.exists():
        return tokens
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return tokens
    skills = data.get("skills") or data.get("items") or []
    if isinstance(data, list):
        skills = data
    for s in skills:
        if not isinstance(s, dict):
            continue
        blob = " ".join([
            str(s.get("name", "")),
            str(s.get("description", "")),
            str(s.get("keywords", "")),
            " ".join(s.get("categories") or []),
        ])
        tokens |= tokenize(blob, query=False)
    return tokens


def _field_coverage(query_toks: set[str], field: str, df: dict[str, int], n: int) -> float:
    if not query_toks or not field:
        return 0.0
    ftoks = tokenize(field, query=False)
    if not ftoks:
        return 0.0
    hit = 0.0
    for t in query_toks:
        if t in ftoks:
            idf = math.log(1 + n / (1 + df.get(t, 0)))
            hit += idf
    return hit / (1 + math.log(1 + len(query_toks)))


def build_df(docs: list[str]) -> tuple[dict[str, int], int]:
    df: dict[str, int] = {}
    for d in docs:
        for t in tokenize(d, query=False):
            df[t] = df.get(t, 0) + 1
    return df, max(len(docs), 1)


def _squash(x: float) -> float:
    """把无界覆盖分压到 (0,1)，避免本机巨大 catalog 撑爆排序。"""
    if x <= 0:
        return 0.0
    return x / (1.0 + x)


def relevance_score(
    candidate: dict,
    interest_toks: set[str],
    df: dict[str, int],
    n: int,
) -> tuple[float, str]:
    """返回 (score, why)。查询侧 = 兴趣 token；文档侧 = 候选元数据。"""
    name = candidate.get("name") or candidate.get("repo", "")
    desc = candidate.get("description") or ""
    # body 只取前 240 字，降低长 SKILL.md 对兴趣词的刷分
    body = (candidate.get("body_preview") or "")[:240]
    kw = candidate.get("keywords") or ""
    ns = _squash(_field_coverage(interest_toks, name, df, n))
    ds = _squash(_field_coverage(interest_toks, desc, df, n))
    ks = _squash(_field_coverage(interest_toks, f"{kw} {body}", df, n))
    score = 0.45 * ns + 0.40 * ds + 0.15 * ks
    if candidate.get("skill_path"):
        score += 0.08
    hay = norm(f"{name} {desc} {kw}")
    domain_hits = [t for t in DOMAIN_TOKENS if t in hay or t in tokenize(hay)]
    if domain_hits:
        score += min(0.12, 0.03 * len(domain_hits))
    why_parts = []
    if ns > 0:
        why_parts.append(f"name:{ns:.2f}")
    if ds > 0:
        why_parts.append(f"desc:{ds:.2f}")
    if ks > 0:
        why_parts.append(f"kw:{ks:.2f}")
    if candidate.get("skill_path"):
        why_parts.append("has:SKILL.md")
    if domain_hits:
        why_parts.append("domain:" + ",".join(domain_hits[:4]))
    return round(min(score, 1.5), 4), (" · ".join(why_parts) if why_parts else "low overlap")


def load_feedback_affinity(data_dir: Path, *, recent: int = 400) -> dict[str, Any]:
    """
    从 feedback.jsonl 构画像：
    - scene_boost / scene_l2_boost
    - repo_boost / repo_penalty
    """
    path = Path(data_dir) / "feedback.jsonl"
    scene_pos: dict[str, float] = {}
    scene_neg: dict[str, float] = {}
    l2_pos: dict[str, float] = {}
    repo_pos: dict[str, float] = {}
    repo_neg: dict[str, float] = {}
    if not path.exists():
        return {
            "scene_boost": {},
            "scene_l2_boost": {},
            "repo_boost": {},
            "repo_penalty": {},
            "events": 0,
        }
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {
            "scene_boost": {},
            "scene_l2_boost": {},
            "repo_boost": {},
            "repo_penalty": {},
            "events": 0,
        }
    lines = [ln for ln in lines if ln.strip()][-recent:]
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        action = obj.get("action") or ""
        scene = (obj.get("scene") or "").strip()
        l2 = (obj.get("scene_l2") or "").strip()
        fn = (obj.get("full_name") or "").strip()
        if action in ("useful", "opened_github"):
            w = 1.0 if action == "useful" else 0.6
            if scene:
                scene_pos[scene] = scene_pos.get(scene, 0) + w
            if l2:
                l2_pos[l2] = l2_pos.get(l2, 0) + w
            if fn:
                repo_pos[fn] = repo_pos.get(fn, 0) + w
        elif action in ("bad", "skip", "wrong_scene"):
            w = 1.0 if action == "bad" else 0.5
            if scene:
                scene_neg[scene] = scene_neg.get(scene, 0) + w
            if fn:
                repo_neg[fn] = repo_neg.get(fn, 0) + w

    def _norm_boost(d: dict[str, float], cap: float = 0.25) -> dict[str, float]:
        if not d:
            return {}
        m = max(d.values()) or 1.0
        return {k: round(cap * (v / m), 4) for k, v in d.items()}

    scene_boost = _norm_boost(scene_pos, 0.22)
    for s, v in scene_neg.items():
        pen = min(0.18, 0.18 * (v / (max(scene_neg.values()) or 1)))
        scene_boost[s] = round(scene_boost.get(s, 0) - pen, 4)

    return {
        "scene_boost": scene_boost,
        "scene_l2_boost": _norm_boost(l2_pos, 0.18),
        "repo_boost": _norm_boost(repo_pos, 0.3),
        "repo_penalty": _norm_boost(repo_neg, 0.35),
        "events": len(lines),
    }


def intent_overlap(item: dict, intent: str) -> tuple[float, str]:
    if not (intent or "").strip():
        return 0.0, ""
    q = tokenize(intent, query=True)
    if not q:
        return 0.0, ""
    blob = " ".join([
        str(item.get("name") or ""),
        str(item.get("description") or ""),
        str(item.get("keywords") or ""),
        str(item.get("scene_label") or ""),
        str(item.get("scene_l2_label") or ""),
    ])
    ftoks = tokenize(blob, query=False)
    hits = [t for t in q if t in ftoks]
    if not hits:
        return 0.0, ""
    score = min(0.45, 0.1 * len(hits) + 0.06 * math.log(1 + len(hits)))
    return round(score, 4), "intent:" + ",".join(hits[:5])


def personalize_score(
    item: dict,
    *,
    affinity: Optional[dict] = None,
    intent: str = "",
) -> tuple[float, str]:
    """
    在 rel_score 之上叠加：意图命中、场景偏好、仓库反馈、星数软加成、来源微调。
    """
    aff = affinity or {}
    base = float(item.get("rel_score") or 0)
    # rel 软归一，保证反馈/意图增量可见
    score = _squash(base) if base > 1 else base
    parts = [f"rel:{score:.2f}"]

    i_score, i_why = intent_overlap(item, intent)
    if i_score:
        score += i_score
        parts.append(i_why)

    scene = item.get("scene") or ""
    l2 = item.get("scene_l2") or ""
    fn = item.get("full_name") or ""
    sb = float((aff.get("scene_boost") or {}).get(scene, 0))
    if sb:
        score += sb
        parts.append(f"pref:{scene}:{sb:+.2f}")
    l2b = float((aff.get("scene_l2_boost") or {}).get(l2, 0))
    if l2b:
        score += l2b
        parts.append(f"pref2:{l2}:{l2b:+.2f}")
    rb = float((aff.get("repo_boost") or {}).get(fn, 0))
    if rb:
        score += rb
        parts.append(f"repo+:{rb:.2f}")
    rp = float((aff.get("repo_penalty") or {}).get(fn, 0))
    if rp:
        score -= rp
        parts.append(f"repo-:{rp:.2f}")

    stars = item.get("stars")
    if isinstance(stars, (int, float)) and stars > 0:
        star_soft = min(0.12, 0.02 * math.log10(1 + stars))
        score += star_soft
        parts.append(f"stars:{star_soft:.2f}")

    source = item.get("source") or ""
    source_bonus = {
        "hellogithub": 0.04,
        "github-search": 0.02,
        "github.com/trending": 0.05,
        "corpus": -0.02,
    }.get(source, 0)
    if source_bonus:
        score += source_bonus
        parts.append(f"src:{source_bonus:+.2f}")

    if item.get("from_corpus"):
        score -= 0.01

    return round(score, 4), " · ".join(parts)


def rerank(
    items: list[dict],
    *,
    affinity: Optional[dict] = None,
    intent: str = "",
) -> list[dict]:
    out: list[dict] = []
    for it in items:
        row = dict(it)
        ps, why = personalize_score(row, affinity=affinity, intent=intent)
        row["personal_score"] = ps
        row["personal_why"] = why
        # 展示用：把个性化理由接到 rel_why 后
        base_why = row.get("rel_why") or ""
        row["rank_why"] = (base_why + " · " + why).strip(" ·")
        out.append(row)
    out.sort(key=lambda x: (
        -float(x.get("personal_score") or 0),
        -float(x.get("rel_score") or 0),
        -int(x.get("stars") or 0),
    ))
    return out
