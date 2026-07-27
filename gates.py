"""Feed 门禁：G_source / G_star / G_rel / G_parse。"""

from __future__ import annotations

from typing import Any, Optional

import rank

DEFAULT_ALLOWED_SOURCES = frozenset({
    "github.com/trending",
    "hellogithub",
    "github-search",
    "corpus",
})

GATE_PROFILES = {
    "loose": {"min_stars": 5, "min_rel": 0.05},
    "standard": {"min_stars": 20, "min_rel": 0.15},
    "strict": {"min_stars": 50, "min_rel": 0.25},
}


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
        if len(name) < 1 or len(desc) < 10:
            summary["rejected"]["G_parse"] += 1
            summary["details"].append({"repo": full_name, "gate": "G_parse", "ok": False})
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
