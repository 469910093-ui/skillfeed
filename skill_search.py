"""意图搜索引擎：关键词 → 读懂意图 → 搜 SKILL.md 全文与多语字段 → 按场景适配排序。

三处搜索共用这一份（以前是三套各自为政的子串匹配）：
- `/api/feed?q=`（ranking.rank_feed 的相关性）
- `/api/geo/skills?q=`（geo.search_items）
- 前端搜索框有 API 时直接问 `/api/feed?q=`，搜的是全库而不只是已加载的卡

一次查询分三步：

1. 读懂意图（understand）
   - 查询里真实出现的词：词表命中（意图簇 triggers、场景关键词、场景名）+ 英文词
   - 意图簇扩展：「生图」→ 海报 / canvas-design / text-to-image …（intent_expand）
   - 场景推断：查询命中哪个一级 / 二级场景；再把该二级场景的多语关键词当弱扩展，
     这是中文查询够到英文 SKILL.md（反之亦然）的桥
2. 检索：每个词取命中它的最高权重字段（名字 > 摘要 > 亮点/场景名 > 正文全文），
   乘词权重与 IDF（到处都有的词不值钱，如 codex / agent）
3. 场景适配：卡片的二级场景 = 推断场景时加分；只有场景对上、文本没命中的，
   排在文本命中之后兜底

不造假词：中文长句先用词表切；词表一个没命中时才退回用户原文的连续汉字段。
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

import intent_expand
import scene

# —— 词权重 ——
W_CORE = 1.0        # 查询里真实出现的词
W_HOST = 0.25       # 宿主名：说的是在哪跑，不是要干什么
W_SEGMENT = 0.6     # 词表没认出时的原文汉字段
W_CLUSTER = 0.7     # 意图簇扩展
W_CLUSTER_STRONG = 0.85
W_SCENE_KW = 0.35   # 推断二级场景的关键词（跨语种桥）

# —— 字段权重（高 → 低，取命中的最高一档）——
F_NAME = 3.0
F_SUMMARY = 2.0
F_DETAIL = 1.5
F_BODY = 1.0
F_REPO = 0.6

FIELD_LABELS = {
    F_NAME: "name", F_SUMMARY: "summary", F_DETAIL: "detail",
    F_BODY: "md", F_REPO: "repo",
}

SCENE_L2_BONUS = 1.0
SCENE_L1_BONUS = 0.4
SCENE_ONLY_REL = 0.04   # 只有场景对上：给一个低于任何文本命中的兜底分
SQUASH_K = 4.0
BODY_MAX_CHARS = 12000

HOST_WORDS = frozenset({
    "codex", "claude", "claude code", "cursor", "openclaw", "gemini cli",
    "windsurf", "copilot", "chatgpt", "gpt",
})
ASCII_STOP = frozenset({
    "a", "an", "the", "and", "or", "of", "to", "for", "in", "on", "with", "by",
    "i", "me", "my", "we", "you", "it", "is", "are", "be", "can", "could",
    "want", "need", "find", "help", "use", "using", "that", "this", "some",
    "skill", "skills", "tool", "tools", "agent skill", "make", "do",
})
CJK_STOP_CHARS = frozenset(
    "的了呢吗啊把被在是有我要帮做一份个能否可以怎么如何请忙去掉删除除下给用到进行以及还"
    "就这那什么哪些为它工具来实现功能需求想找让些系列"
)

_CJK = re.compile(r"[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]")
_ASCII_WORD = re.compile(r"[a-z0-9][a-z0-9.+#_-]*")


@dataclass
class Query:
    raw: str
    terms: dict[str, float] = field(default_factory=dict)
    core: set[str] = field(default_factory=set)
    strong: set[str] = field(default_factory=set)
    scenes: dict[str, float] = field(default_factory=dict)
    scenes_l2: dict[str, float] = field(default_factory=dict)

    def add(self, term: str, weight: float, *, core: bool = False) -> None:
        t = (term or "").strip().lower()
        if len(t) < 2:
            return
        if weight > self.terms.get(t, 0.0):
            self.terms[t] = weight
        if core:
            self.core.add(t)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _vocabulary() -> list[tuple[str, str, str]]:
    """[(词, 一级, 二级)]：场景关键词 + 场景名（中英），长的优先。"""
    rows: list[tuple[str, str, str]] = []
    for sid, kws in scene.RULES:
        for kw in kws:
            rows.append((kw.lower(), sid, ""))
    for parent, kids in scene.SCENES_L2.items():
        for cid, label, kws in kids:
            rows.append((label.lower(), parent, cid))
            en = scene.SCENE_L2_LABELS_EN.get(cid, "")
            if en:
                rows.append((en.lower(), parent, cid))
            for kw in kws:
                rows.append((kw.lower(), parent, cid))
    for sid, label in scene.SCENES:
        if sid == "other":
            continue
        rows.append((label.lower(), sid, ""))
        en = scene.SCENE_LABELS_EN.get(sid, "")
        if en:
            rows.append((en.lower(), sid, ""))
    rows.sort(key=lambda r: -len(r[0]))
    return rows


_VOCAB = _vocabulary()
_WORD_RE_CACHE: dict[str, re.Pattern] = {}


def _contains(text: str, term: str) -> bool:
    """短英文词（≤3 字符，如 ui / ppt）按词边界匹配，其余子串匹配。"""
    if not text:
        return False
    if len(term) <= 3 and term.isascii():
        pat = _WORD_RE_CACHE.get(term)
        if pat is None:
            pat = re.compile(r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])")
            _WORD_RE_CACHE[term] = pat
        return bool(pat.search(text))
    return term in text


def understand(query: str) -> Query:
    raw = _norm(query)
    q = Query(raw=raw)
    if not raw:
        return q
    compact = raw.replace(" ", "")

    # 1) 原文整句（短句才有意义）
    if len(compact) <= 12:
        q.add(raw, W_CORE, core=True)

    # 2) 英文词
    for w in _ASCII_WORD.findall(raw):
        w = w.strip(".-_")
        if not w or w in ASCII_STOP:
            continue
        q.add(w, W_HOST if w in HOST_WORDS else W_CORE, core=w not in HOST_WORDS)

    # 3) 意图簇；命中的中文触发词先从原文里扣掉，免得被场景词表里更短的词
    #    再认一遍（「架构图」不该再被「架构」拉去工程开发）
    taken = compact
    for cluster in intent_expand.CLUSTERS:
        hit = [t for t in cluster.get("triggers") or () if t and (t in raw or t in compact)]
        if not hit:
            continue
        for t in sorted(hit, key=len, reverse=True):
            q.add(t, W_CORE, core=True)
            if _CJK.search(t):
                taken = taken.replace(t.replace(" ", ""), " ")
        strong = {s.lower() for s in cluster.get("strong") or ()}
        for t in cluster.get("expand") or ():
            t = t.lower()
            q.add(t, W_CLUSTER_STRONG if t in strong else W_CLUSTER)
        q.strong |= strong
        for sid, l2 in cluster.get("scenes") or ():
            q.scenes[sid] = q.scenes.get(sid, 0.0) + 2.0
            if l2:
                q.scenes_l2[l2] = q.scenes_l2.get(l2, 0.0) + 2.0

    # 4) 场景词表：查询里真实出现的场景关键词 / 场景名
    cluster_hit = taken != compact
    vocab_hit = cluster_hit
    matched: set[str] = set()
    for word, sid, l2 in _VOCAB:
        if not word or word in HOST_WORDS:
            continue
        probe = word.replace(" ", "") if _CJK.search(word) else word
        if _CJK.search(word):
            # 同一个词在一级和二级词表里各出现一次（如「周报」），两边的场景都要记上；
            # 已被更长的词吃掉的短词不再单独算（「架构图」吃掉「架构」）
            if probe not in matched:
                if probe not in taken:
                    continue
                taken = taken.replace(probe, " ")
                matched.add(probe)
        elif not _contains(raw, word):
            continue
        vocab_hit = True
        q.add(word, W_CORE, core=True)
        q.scenes[sid] = q.scenes.get(sid, 0.0) + 1.0
        if l2:
            q.scenes_l2[l2] = q.scenes_l2.get(l2, 0.0) + 1.0

    # 5) 词表一个没认出：退回原文连续汉字段（不滑窗）
    if not vocab_hit and not any(t for t in q.core if _CJK.search(t) and t != raw):
        segs = re.split(r"[^\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]+", taken)
        for seg in segs:
            seg = "".join(ch if ch not in CJK_STOP_CHARS else " " for ch in seg)
            for part in seg.split():
                if 2 <= len(part) <= 8:
                    q.add(part, W_SEGMENT, core=True)

    # 6) 推断场景 → 二级场景关键词当跨语种弱扩展（只取最强的二级）
    if q.scenes_l2:
        top = max(q.scenes_l2.values())
        keep = {k: v for k, v in q.scenes_l2.items() if v >= top}
        q.scenes_l2 = keep
        for parent, kids in scene.SCENES_L2.items():
            for cid, label, kws in kids:
                if cid not in keep:
                    continue
                q.scenes.setdefault(parent, 1.0)
                q.add(label, W_SCENE_KW)
                for kw in kws:
                    q.add(kw, W_SCENE_KW)
    if q.scenes:
        top = max(q.scenes.values())
        q.scenes = {k: v for k, v in q.scenes.items() if v >= top * 0.5}
    return q


def _join(*parts) -> str:
    out = []
    for p in parts:
        if isinstance(p, (list, tuple)):
            p = " ".join(str(x) for x in p)
        if p:
            out.append(str(p))
    return " ".join(out).lower()


def doc_fields(item: dict, md_text: str = "") -> list[tuple[float, str]]:
    fm = item.get("frontmatter") or {}
    body = md_text or str(item.get("body_preview") or "")
    return [
        (F_NAME, _join(item.get("name"), item.get("dir_name"), item.get("skill_path"))),
        (F_SUMMARY, _join(
            item.get("one_liner_zh"), item.get("one_liner_en"), item.get("one_liner"),
            item.get("description"), item.get("keywords"),
            fm.get("tags") if isinstance(fm, dict) else "",
        )),
        (F_DETAIL, _join(
            item.get("highlights_zh"), item.get("highlights_en"), item.get("highlights"),
            item.get("problem"), item.get("who_for_zh"), item.get("who_for_en"),
            item.get("scene_label"), item.get("scene_label_en"),
            item.get("scene_l2_label"), item.get("scene_l2_label_en"),
        )),
        (F_BODY, body[:BODY_MAX_CHARS].lower()),
        (F_REPO, _join(item.get("full_name"), item.get("repo_description"))),
    ]


@dataclass
class Hit:
    item: dict
    rel: float
    why: str
    terms: list[tuple[str, str]]


def search(
    items: Iterable[dict],
    query: str,
    *,
    md_lookup: Optional[Callable[[dict], str]] = None,
) -> list[Hit]:
    """返回按相关性降序的命中（未命中的不返回）。"""
    q = understand(query)
    rows = list(items)
    if not q.terms or not rows:
        return []

    docs = [doc_fields(it, md_lookup(it) if md_lookup else "") for it in rows]
    n = len(docs)
    per_doc: list[dict[str, float]] = []
    df: dict[str, int] = {}
    for fields in docs:
        hits: dict[str, float] = {}
        for term in q.terms:
            for fw, text in fields:
                if _contains(text, term):
                    hits[term] = fw
                    break
        for t in hits:
            df[t] = df.get(t, 0) + 1
        per_doc.append(hits)

    log_n = math.log(1 + n)
    out: list[Hit] = []
    seen: set[tuple[str, str]] = set()
    for i, it in enumerate(rows):
        hits = per_doc[i]
        key = (str(it.get("full_name") or it.get("id") or ""), str(it.get("skill_path") or ""))
        if key[0] and key in seen:
            continue
        seen.add(key)
        score = 0.0
        contrib: list[tuple[float, str, float]] = []
        core_hit = False
        strong_hit = False
        exp_hits = 0
        for term, fw in hits.items():
            idf = math.log(1 + n / (1 + df.get(term, 0))) / log_n if log_n else 1.0
            s = q.terms[term] * fw * max(idf, 0.15)
            score += s
            contrib.append((s, term, fw))
            if term in q.core and q.terms[term] >= W_SEGMENT:
                core_hit = True
            elif term in q.strong and fw >= F_BODY:
                strong_hit = True
            else:
                exp_hits += 1
        l2_match = bool(q.scenes_l2) and (it.get("scene_l2") or "") in q.scenes_l2
        l1_match = bool(q.scenes) and (it.get("scene") or "") in q.scenes
        text_ok = core_hit or strong_hit or exp_hits >= 2
        if not text_ok and not l2_match:
            continue
        if l2_match:
            score += SCENE_L2_BONUS
        elif l1_match and text_ok:
            score += SCENE_L1_BONUS
        rel = score / (score + SQUASH_K)
        if not text_ok:
            rel = min(rel, SCENE_ONLY_REL)
        contrib.sort(key=lambda x: -x[0])
        terms = [(t, FIELD_LABELS.get(fw, "")) for _s, t, fw in contrib[:4]]
        why_bits = [f"{t}@{f}" for t, f in terms]
        if l2_match:
            why_bits.append("scene:" + str(it.get("scene_l2")))
        elif l1_match and text_ok:
            why_bits.append("scene:" + str(it.get("scene")))
        out.append(Hit(item=it, rel=round(rel, 4), why=" ".join(why_bits), terms=terms))

    out.sort(key=lambda h: (-h.rel, -(h.item.get("stars") or 0)))
    return out


def relevance_map(
    items: Iterable[dict],
    query: str,
    *,
    md_lookup: Optional[Callable[[dict], str]] = None,
) -> dict[int, Hit]:
    """id(item) → Hit。rank_feed 里按对象身份回查，避免同名条目串分。"""
    return {id(h.item): h for h in search(items, query, md_lookup=md_lookup)}
