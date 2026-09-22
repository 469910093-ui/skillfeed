#!/usr/bin/env python3
"""Harvest GitHub agent-skills (default stars>=2000) → 飞书底表 + skill-feed.

召回策略：仓库搜索按关键词 × 星数区间分片（避开单查询 1000 条上限），
再探测 SKILL.md / skills / .claude/skills 等，只留 skill 形。
`--min-stars 1000` 会补上 1k–2k 切片；领域词必须绑 skill 信号。
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import scene  # noqa: E402
from crawl_waytoagi_wiki import (  # noqa: E402
    list_bitable_names,
    load_existing_names,
    push_rows,
    save_pushed_names,
)
from gate_waytoagi_feed import probe_root  # noqa: E402
from gates import description_shape_reason  # noqa: E402
from ingest_waytoagi import ingest_corpus, merge_feed  # noqa: E402
from ingest_waytoagi_candidates import merge_items  # noqa: E402

HOME = Path.home()
DATA = HOME / ".skill-feed"
OUT = DATA / "bitable_export" / "github_2k_skills"
MIN_STARS = 2000
SEARCH_SLEEP = 2.2

# 星数切片：把热门查询拆到每片 <1000 条。2k+ 为默认；1k 门槛再补低段。
STAR_SLICES_2K = (
    "2000..2499",
    "2500..3499",
    "3500..4999",
    "5000..7999",
    "8000..14999",
    "15000..49999",
    ">=50000",
)
STAR_SLICES = STAR_SLICES_2K


def star_slices_for(min_stars: int) -> tuple[str, ...]:
    slices: list[str] = []
    floor = max(int(min_stars), 1)
    if floor < 2000:
        prev = floor
        for end in (1299, 1599, 1999):
            if end < floor:
                continue
            slices.append(f"{prev}..{end}")
            prev = end + 1
    slices.extend(STAR_SLICES_2K)
    return tuple(slices)


def band_label(min_stars: int) -> str:
    if min_stars >= 1000 and min_stars % 1000 == 0:
        return f"GitHub · {min_stars // 1000}k+ skill"
    return f"GitHub · {min_stars}+ skill"

BASE_QUERIES = (
    "SKILL.md",
    '"SKILL.md"',
    "topic:agent-skills",
    "topic:claude-skills",
    "topic:claude-skill",
    '"agent skills"',
    '"claude skill"',
    '"cursor skill"',
    '"agent skill"',
    "skills in:name",
    "skill.md in:name",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def gh_search(q: str, page: int = 1, retries: int = 6) -> dict:
    for attempt in range(retries):
        p = subprocess.run(
            [
                "gh",
                "api",
                "-X",
                "GET",
                "search/repositories",
                "-f",
                f"q={q}",
                "-f",
                "sort=stars",
                "-f",
                "order=desc",
                "-F",
                "per_page=100",
                "-F",
                f"page={page}",
            ],
            capture_output=True,
        )
        if p.returncode == 0:
            return json.loads(p.stdout.decode("utf-8", errors="replace"))
        err = (p.stderr or p.stdout).decode("utf-8", errors="replace")[:400]
        low = err.lower()
        if "rate limit" in low or "403" in err or "abuse" in low:
            wait = min(180, 45 * (attempt + 1))
            print(f"[search] rate-limit {q} p{page}, sleep {wait}s", flush=True)
            time.sleep(wait)
            continue
        print(f"[search] FAIL {q} p{page}: {err}", flush=True)
        return {"total_count": 0, "items": [], "error": err}
    return {"total_count": 0, "items": [], "error": "rate limit retries exhausted"}


def topic_queries(topics: list[str]) -> tuple[str, ...]:
    """用户给的领域词必须绑上 skill 信号，否则 code/video 会捞到整个 GitHub。"""
    out: list[str] = []
    extras = {
        "short": ("short-video", "short video", "shortform"),
        "video": ("video skill",),
        "paper": ("arxiv", "paper skill"),
        "translation": ("i18n", "translate"),
        "code": ("coding skill",),
        "ppt": ("powerpoint", "pptx", "slides"),
        "feishu": ("lark", "飞书"),
        "excel": ("spreadsheet", "xlsx"),
        "design": ("ui-design", "figma"),
        "seo": ("search-engine",),
        "geo": ("generative-engine", "geo seo"),
        "dsh": ("dashboard",),
        "mcp": ("mcp server", "model-context-protocol"),
    }
    for raw in topics:
        t = raw.strip()
        if not t:
            continue
        words = (t,) + extras.get(t.lower(), ())
        for w in words:
            out.append(f"{w} skill")
            out.append(f'{w} SKILL.md')
            out.append(f'{w} "agent skills"')
    # 去重且保序
    seen: set[str] = set()
    uniq: list[str] = []
    for q in out:
        if q in seen:
            continue
        seen.add(q)
        uniq.append(q)
    return tuple(uniq)


def harvest_search(
    bases: tuple[str, ...] | None = None,
    *,
    min_stars: int = MIN_STARS,
    slices: tuple[str, ...] | None = None,
    sleep: float = SEARCH_SLEEP,
) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for base in bases or BASE_QUERIES:
        for sl in slices or STAR_SLICES:
            q = f"{base} stars:{sl}"
            first = gh_search(q, 1)
            if first.get("error"):
                time.sleep(max(sleep, 2))
                continue
            total = int(first.get("total_count") or 0)
            items = list(first.get("items") or [])
            pages = min(10, (total + 99) // 100) if total else 1
            print(f"[search] {total:5d}  {q}", flush=True)
            if total <= 0:
                time.sleep(max(sleep, 2))
                continue
            for page in range(2, pages + 1):
                time.sleep(sleep)
                chunk = gh_search(q, page)
                items.extend(chunk.get("items") or [])
                if chunk.get("error"):
                    break
            for repo in items:
                fn = (repo.get("full_name") or "").strip()
                if not fn:
                    continue
                stars = int(repo.get("stargazers_count") or 0)
                if stars < min_stars:
                    continue
                rec = found.setdefault(
                    fn.lower(),
                    {
                        "full_name": fn,
                        "stars": stars,
                        "description": repo.get("description") or "",
                        "html_url": repo.get("html_url") or f"https://github.com/{fn}",
                        "pushed_at": (repo.get("pushed_at") or "")[:16],
                        "owner": (repo.get("owner") or {}).get("login") or fn.split("/")[0],
                        "name": repo.get("name") or fn.split("/")[-1],
                        "queries": [],
                    },
                )
                rec["stars"] = max(int(rec.get("stars") or 0), stars)
                rec["queries"].append(q)
            time.sleep(sleep)
    return found


def to_bitable_row(meta: dict, skill_path: str) -> dict:
    fn = meta["full_name"]
    return {
        "名称": (meta.get("name") or fn.split("/")[-1])[:200],
        "仓库全名": fn,
        "来源": "GitHub Search",
        "发布人": meta.get("owner") or fn.split("/")[0],
        "发布时间": (meta.get("pushed_at") or "")[:16],
        "GitHub链接": meta.get("html_url") or f"https://github.com/{fn}",
        "分类": "开发",
        "二级分类": meta.get("band_label") or "GitHub · 2k+ skill",
        "关键词": f"github-2k-skills · {skill_path} · " + " · ".join((meta.get("queries") or [])[:2]),
        "评星": int(meta.get("stars") or 0),
        "描述": (meta.get("description") or "")[:500],
        "收录时间": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"),
        "数据池": "知识库",
    }


def to_feed_item(meta: dict, skill_path: str) -> dict:
    fn = meta["full_name"]
    owner, name = fn.split("/", 1)
    desc = (meta.get("description") or "")[:500]
    row = {
        "id": f"gh2k:{fn}",
        "full_name": fn,
        "name": meta.get("name") or name,
        "owner": owner,
        "description": desc,
        "url": meta.get("html_url") or f"https://github.com/{fn}",
        "source": "github-search",
        "kind": "skill",
        "mode": "skills",
        "hg_section": meta.get("hg_section") or "GitHub 2k+",
        "skill_path": skill_path,
        "stars": int(meta.get("stars") or 0),
        "stars_today": 0,
        "body_preview": desc[:1200],
        "ingested_at": _now(),
        "from_corpus": True,
    }
    return scene.apply_scene(row)


def write_harvest_status(status: str, detail: str, extra: dict) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": status,
        "checked_at": _now(),
        "detail": detail,
        "must_notify": status != "UPDATED",
        **extra,
    }
    (OUT / "latest-ingest-status.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if status != "UPDATED":
        (OUT / "INGEST_ALERT.md").write_text(
            f"# GitHub 2k+ skills harvest alert\n\n- status: **{status}**\n- {detail}\n\n"
            "必须用简体中文通知用户，禁止说刷新成功。\n",
            encoding="utf-8",
        )


def process_found(
    found: dict[str, dict],
    existing: set[str],
    *,
    min_stars: int,
) -> dict:
    """Probe + push + ingest. Mutates existing with newly pushed names."""
    label = band_label(min_stars)
    section = f"GitHub {min_stars // 1000}k+" if min_stars >= 1000 else f"GitHub {min_stars}+"
    for rec in found.values():
        rec["band_label"] = label
        rec["hg_section"] = section

    pending = [rec for rec in found.values() if rec["full_name"].lower() not in existing]
    print(f"[probe] pending={len(pending)} already_in_table={len(found) - len(pending)}", flush=True)
    empty = {
        "hits": len(found),
        "pending": len(pending),
        "kept": 0,
        "rows": 0,
        "items": 0,
        "already": len(found) - len(pending),
        "corpus_added": 0,
        "fatal": "",
        "empty": True,
    }
    if not pending:
        print("[NO_NEW] all hits already in bitable")
        return empty

    kept: list[tuple[dict, str]] = []
    miss_probe: list[str] = []
    for i, rec in enumerate(pending, 1):
        fn = rec["full_name"]
        desc = rec.get("description") or ""
        name = rec.get("name") or fn.split("/")[-1]
        if len(name) < 1 or (desc and description_shape_reason(desc, name) == "shape_pure_path"):
            miss_probe.append(fn)
            continue
        sp = ""
        try:
            sp = probe_root(fn)
        except Exception:  # noqa: BLE001
            pass
        if not sp:
            miss_probe.append(fn)
            continue
        kept.append((rec, sp))
        if i % 20 == 0:
            print(f"[probe] {i}/{len(pending)} kept={len(kept)}", flush=True)
        time.sleep(0.05)

    prev_miss = []
    if (OUT / "miss_probe.json").exists():
        try:
            prev_miss = json.loads((OUT / "miss_probe.json").read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            prev_miss = []
    (OUT / "miss_probe.json").write_text(
        json.dumps(sorted(set(prev_miss) | set(miss_probe)), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[probe] skill-shaped={len(kept)} dropped={len(miss_probe)}", flush=True)
    if not kept:
        print("[NO_NEW] no skill-shaped repos")
        return empty

    rows: list[dict] = []
    feed_items: list[dict] = []
    already = 0
    for rec, sp in kept:
        fn = rec["full_name"]
        feed_items.append(to_feed_item(rec, sp))
        if fn.lower() in existing:
            already += 1
            continue
        rows.append(to_bitable_row(rec, sp))

    (OUT / "preview.json").write_text(
        json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[bitable] new={len(rows)} already={already} feed_candidates={len(feed_items)}")

    if rows:
        try:
            push_rows(rows)
        except Exception as e:  # noqa: BLE001
            print(f"[FAIL] bitable: {e}")
            return {**empty, "kept": len(kept), "rows": len(rows), "fatal": str(e), "empty": False}
        for row in rows:
            existing.add((row.get("仓库全名") or "").lower())
        save_pushed_names(existing)
    else:
        print("[bitable] nothing new to push")

    snap = ingest_corpus(feed_items)
    n_corpus = merge_feed(feed_items)
    n_items = merge_items(feed_items)
    print(f"[feed] corpus+{snap['added']} corpus_feed+{n_corpus} items+{n_items}")
    return {
        "hits": len(found),
        "pending": len(pending),
        "kept": len(kept),
        "rows": len(rows),
        "items": n_items,
        "already": already,
        "corpus_added": snap["added"],
        "fatal": "",
        "empty": False,
    }


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--topics",
        default="",
        help="comma-separated domain words (e.g. code,video,paper); each is AND-ed with skill signals",
    )
    ap.add_argument(
        "--topics-only",
        action="store_true",
        help="only run --topics queries, skip the default SKILL.md / topic:agent-skills set",
    )
    ap.add_argument(
        "--min-stars",
        type=int,
        default=MIN_STARS,
        help="star floor (default 2000; pass 1000 to also harvest 1k–2k)",
    )
    args = ap.parse_args()
    min_stars = max(int(args.min_stars), 1)
    slices = star_slices_for(min_stars)
    topics = [x.strip() for x in args.topics.split(",") if x.strip()]
    if args.topics_only and topics:
        waves = [(t, topic_queries([t])) for t in topics]
    elif topics:
        waves = [("(base+topics)", BASE_QUERIES + topic_queries(topics))]
    else:
        waves = [("(base)", BASE_QUERIES)]

    n_q = sum(len(b) for _, b in waves)
    print(
        f"[queries] waves={len(waves)} bases={n_q} × {len(slices)} slices  min_stars={min_stars}",
        flush=True,
    )

    OUT.mkdir(parents=True, exist_ok=True)
    print("[sync] pull bitable names…", flush=True)
    try:
        remote = list_bitable_names()
    except Exception as e:  # noqa: BLE001
        write_harvest_status("PUSH_FAILED", f"bitable list failed: {e}", {})
        print(f"[FAIL] bitable list: {e}")
        return 1
    existing = load_existing_names() | remote
    save_pushed_names(existing)
    print(f"[sync] bitable+local existing={len(existing)}", flush=True)

    all_found: dict[str, dict] = {}
    totals = {"hits": 0, "kept": 0, "rows": 0, "items": 0, "already": 0, "corpus_added": 0}
    fatal = ""
    for i, (wave_name, bases) in enumerate(waves, 1):
        print(f"\n===== [{i}/{len(waves)}] {wave_name}  queries={len(bases)} =====", flush=True)
        found = harvest_search(bases, min_stars=min_stars, slices=slices)
        if wave_name == "(base)" or wave_name == "(base+topics)":
            for seed in ("Zafer-Liu/Data-Analysis-Agent",):
                if seed.lower() in found:
                    continue
                p = subprocess.run(["gh", "api", f"repos/{seed}"], capture_output=True)
                if p.returncode != 0:
                    print(f"[seed] miss {seed}")
                    continue
                repo = json.loads(p.stdout.decode("utf-8", errors="replace"))
                stars = int(repo.get("stargazers_count") or 0)
                if stars < min_stars:
                    continue
                found[seed.lower()] = {
                    "full_name": repo.get("full_name") or seed,
                    "stars": stars,
                    "description": repo.get("description") or "",
                    "html_url": repo.get("html_url") or f"https://github.com/{seed}",
                    "pushed_at": (repo.get("pushed_at") or "")[:16],
                    "owner": (repo.get("owner") or {}).get("login") or seed.split("/")[0],
                    "name": repo.get("name") or seed.split("/")[-1],
                    "queries": ["seed"],
                }
                print(f"[seed] +{seed} {stars}★")
        all_found.update(found)
        (OUT / "search_hits.json").write_text(
            json.dumps(all_found, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"[search] wave unique={len(found)} running_total={len(all_found)}", flush=True)
        if not found:
            print(f"[search] empty wave {wave_name}")
            continue
        stats = process_found(found, existing, min_stars=min_stars)
        totals["hits"] += stats["hits"]
        totals["kept"] += stats["kept"]
        totals["rows"] += stats["rows"]
        totals["items"] += stats["items"]
        totals["already"] += stats["already"]
        totals["corpus_added"] += stats["corpus_added"]
        (OUT / "topic_progress.jsonl").open("a", encoding="utf-8").write(
            json.dumps(
                {
                    "topic": wave_name,
                    "wave": i,
                    "unique": len(found),
                    **{k: stats[k] for k in ("kept", "rows", "items", "already", "fatal")},
                    "at": _now(),
                },
                ensure_ascii=False,
            )
            + "\n"
        )
        if stats["fatal"]:
            fatal = stats["fatal"]
            break

    print(
        f"\n[done] waves={len(waves)} unique={len(all_found)} "
        f"skill={totals['kept']} bitable+{totals['rows']} items+{totals['items']}",
        flush=True,
    )
    if fatal:
        write_harvest_status("PUSH_FAILED", fatal, totals)
        return 1
    if not all_found:
        write_harvest_status("FETCH_FAILED", "search returned 0 repos", {"hits": 0})
        print("[FAIL] search empty")
        return 1
    if totals["rows"] == 0 and totals["items"] == 0 and totals["corpus_added"] == 0:
        write_harvest_status(
            "NO_NEW",
            f"topic search hits={len(all_found)} all already in bitable/feed",
            {"hits": len(all_found), "kept": totals["kept"]},
        )
        print("[NO_NEW] all hits already in bitable/feed")
        return 2

    write_harvest_status(
        "UPDATED",
        f"hits={len(all_found)} skill={totals['kept']} bitable+{totals['rows']} items+{totals['items']}",
        {
            "hits": len(all_found),
            "skill_shaped": totals["kept"],
            "bitable_new": totals["rows"],
            "already": totals["already"],
            "corpus_added": totals["corpus_added"],
            "items_new": totals["items"],
            "min_stars": min_stars,
            "topics": topics,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
