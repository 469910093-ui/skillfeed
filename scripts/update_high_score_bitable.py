#!/usr/bin/env python3
"""从当前 feed.json 筛高分 skills，写入飞书多维表格（来源保留真实 source）。

用法:
  python scripts/update_high_score_bitable.py [--min-stars 100] [--min-score 0.2] [--top 80]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from export_to_bitable import (  # noqa: E402
    SOURCE_LABELS,
    classify,
    keywords_for,
    run_lark,
)

HOME = Path.home()
DATA = HOME / ".skill-feed"
FEED = DATA / "feed.json"
TARGET = DATA / "bitable_export" / "target.json"
OUT = DATA / "bitable_export" / "high_score"


def stars_of(x: dict) -> int:
    try:
        return int(x.get("stars") or 0)
    except (TypeError, ValueError):
        return 0


def score_of(x: dict) -> float:
    for k in ("personal_score", "rel_score"):
        try:
            return float(x.get(k) or 0)
        except (TypeError, ValueError):
            pass
    return 0.0


def source_label(raw: str) -> str:
    return SOURCE_LABELS.get(raw or "", raw or "未知")


def load_pool() -> list[dict]:
    data = json.loads(FEED.read_text(encoding="utf-8"))
    items = list(data.get("items") or [])
    corpus = list(data.get("corpus") or [])
    # 主 Feed 优先；corpus 里只收有 stars 的 skill 形条目
    pool: dict[str, dict] = {}
    for x in items:
        fn = (x.get("full_name") or "").strip()
        if fn:
            pool[fn.lower()] = dict(x)
    for x in corpus:
        fn = (x.get("full_name") or "").strip()
        if not fn:
            continue
        key = fn.lower()
        if key in pool:
            # 保留更高分/星
            prev = pool[key]
            if stars_of(x) > stars_of(prev) or score_of(x) > score_of(prev):
                merged = dict(prev)
                merged.update({k: v for k, v in x.items() if v not in (None, "", [])})
                # 不让 corpus 覆盖真实非 hellogithub source
                if prev.get("source") and prev.get("source") not in ("corpus", "hellogithub"):
                    merged["source"] = prev["source"]
                pool[key] = merged
            continue
        kind = (x.get("kind") or "").lower()
        if kind in ("skill", "") or x.get("skill_path") or stars_of(x) > 0:
            if stars_of(x) > 0 or score_of(x) > 0:
                pool[key] = dict(x)
    return list(pool.values())


def to_row(item: dict) -> dict:
    fn = item["full_name"]
    owner = (item.get("owner") or "").strip() or fn.split("/")[0]
    url = (item.get("url") or item.get("skill_url") or f"https://github.com/{fn}").strip()
    ing = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")
    s = stars_of(item)
    row = {
        "名称": (item.get("name") or fn.split("/")[-1])[:200],
        "仓库全名": fn,
        "来源": source_label(str(item.get("source") or "")),
        "发布人": owner,
        "发布时间": (item.get("github_pushed_at") or item.get("ingested_at") or "")[:16],
        "GitHub链接": url,
        "分类": classify(item),
        "二级分类": (item.get("scene_l2_label") or item.get("hg_section") or "")[:100],
        "关键词": keywords_for(item, fn),
        "描述": (item.get("description") or item.get("one_liner") or "")[:500],
        "收录时间": ing,
        "数据池": "主Feed",
    }
    if s:
        row["评星"] = s
    issue = item.get("issue")
    if issue not in (None, ""):
        try:
            row["HelloGitHub期数"] = int(issue)
        except (TypeError, ValueError):
            pass
    return row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-stars", type=int, default=100)
    ap.add_argument("--min-score", type=float, default=0.0)
    ap.add_argument("--top", type=int, default=80)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not FEED.is_file():
        print("missing feed.json，先跑 python skillfeed.py refresh")
        return 2

    pool = load_pool()
    high = [
        x for x in pool
        if stars_of(x) >= args.min_stars and score_of(x) >= args.min_score
    ]
    high.sort(key=lambda x: (stars_of(x), score_of(x)), reverse=True)
    high = high[: args.top]

    print(f"[high] pool={len(pool)} matched={len(high)} min_stars={args.min_stars}")
    for x in high[:30]:
        print(
            f"  {stars_of(x):6d} | {str(x.get('source') or '?'):18s} | "
            f"{x.get('full_name')} | {(x.get('name') or '')[:36]}"
        )

    if not high:
        print("[high] 无匹配，退出")
        return 1

    rows = [to_row(x) for x in high]
    OUT.mkdir(parents=True, exist_ok=True)
    batch = OUT / "batch_001.json"
    batch.write_text(json.dumps({"create_records": rows}, ensure_ascii=False), encoding="utf-8")
    (OUT / "preview.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.dry_run:
        print(f"[dry-run] wrote {batch}")
        return 0

    target = json.loads(TARGET.read_text(encoding="utf-8"))
    bt, tid = target["base_token"], target["table_id"]
    print(f"[bitable] push {len(rows)} → {bt} / {tid}")
    run_lark(
        [
            "base", "+record-batch-create",
            "--as", "user",
            "--base-token", bt,
            "--table-id", tid,
            "--json", "@batch_001.json",
        ],
        cwd=OUT,
    )
    print(f"[done] {len(rows)} 条高分 skills 已写入多维表格")
    print(f"URL: https://trip.larkenterprise.com/base/{bt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
