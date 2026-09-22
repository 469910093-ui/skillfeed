#!/usr/bin/env python3
"""把 gate_waytoagi_feed 筛出的 NEW 候选灌进 corpus + feed.json。"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import scene  # noqa: E402
from ingest_waytoagi import ingest_corpus, merge_feed  # noqa: E402

HOME = Path.home()
DATA = HOME / ".skill-feed"
FEED = DATA / "feed.json"
OUT = DATA / "bitable_export" / "waytoagi_wiki"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_bitable() -> dict[str, dict]:
    from gate_waytoagi_feed import load_bottom

    return load_bottom()


def cand_to_item(c: dict, bitable: dict[str, dict]) -> dict:
    fn = c["full_name"]
    if "/" not in fn:
        owner, name = "", fn
    else:
        owner, name = fn.split("/", 1)
    br = bitable.get(fn.lower()) or {}
    desc = (c.get("description") or br.get("描述") or "")[:500]
    kind = (c.get("kind") or "skill").strip() or "skill"
    row = {
        "id": f"wagi:{fn}",
        "full_name": fn,
        "name": br.get("名称") or name,
        "owner": owner,
        "description": desc,
        "url": br.get("GitHub链接") or f"https://github.com/{fn}",
        "source": "catalog",
        "kind": kind,
        "mode": "skills" if kind == "skill" else "ai",
        "hg_section": "WaytoAGI",
        "skill_path": c.get("skill_path") or "",
        "stars": int(c.get("stars") or br.get("评星") or 0),
        "stars_today": 0,
        "topic": (br.get("关键词") or "")[:200],
        "body_preview": desc[:1200],
        "ingested_at": _now(),
        "from_corpus": True,
    }
    return scene.apply_scene(row)


def collect_mcp(bitable: dict[str, dict], already: set[str]) -> list[dict]:
    from gate_waytoagi_feed import is_mcp_repo
    from gates import description_shape_reason

    out: list[dict] = []
    for rec in bitable.values():
        fn = (rec.get("仓库全名") or "").strip()
        if not fn or fn.lower() in already:
            continue
        name = rec.get("名称") or fn.split("/")[-1]
        desc = (rec.get("描述") or "").strip()
        if not is_mcp_repo(fn, name, desc):
            continue
        stars = int(rec.get("评星") or 0)
        if stars < 20:
            continue
        if len(name) < 1 or len(desc) < 10 or description_shape_reason(desc, name):
            continue
        out.append(
            {
                "full_name": fn,
                "stars": stars,
                "skill_path": "",
                "kind": "mcp",
                "description": desc[:80],
            }
        )
    out.sort(key=lambda x: -int(x.get("stars") or 0))
    return out


def merge_items(new_items: list[dict]) -> int:
    if not FEED.is_file():
        print("[merge-items] no feed.json")
        return 0
    data = json.loads(FEED.read_text(encoding="utf-8"))
    items = list(data.get("items") or [])
    have = {(x.get("full_name") or "").lower() for x in items}
    inserted = 0
    head: list[dict] = []
    for it in new_items:
        key = it["full_name"].lower()
        if key in have:
            continue
        head.append(it)
        have.add(key)
        inserted += 1
    data["items"] = head + items
    data["waytoagi_candidates_ingested_at"] = _now()
    FEED.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return inserted


def write_status(status: str, detail: str, extra: dict) -> None:
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
            f"# WaytoAGI candidates ingest alert\n\n- status: **{status}**\n- {detail}\n\n"
            "必须用简体中文通知用户，禁止说刷新成功。\n",
            encoding="utf-8",
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only-new", action="store_true", default=True)
    ap.add_argument("--mcp", action="store_true", help="also ingest MCP repos from 底表")
    ap.add_argument("--mcp-only", action="store_true", help="only ingest MCP, skip skill NEW")
    args = ap.parse_args()

    cand_path = OUT / "feed_candidates.json"
    rows: list[dict] = []
    if not args.mcp_only:
        if not cand_path.is_file():
            write_status("FETCH_FAILED", "missing feed_candidates.json", {})
            print("[FAIL] missing feed_candidates.json")
            return 1
        rows = json.loads(cand_path.read_text(encoding="utf-8"))
        if not isinstance(rows, list):
            rows = []
        if args.only_new:
            rows = [r for r in rows if (r.get("feed") or "") == "NEW"]
        for r in rows:
            r.setdefault("kind", "skill")

    bitable = load_bitable()
    already: set[str] = set()
    if FEED.is_file():
        feed = json.loads(FEED.read_text(encoding="utf-8"))
        if not isinstance(feed, dict):
            feed = {}
        already = {(x.get("full_name") or "").lower() for x in (feed.get("items") or [])}
    if args.mcp or args.mcp_only:
        mcp_rows = collect_mcp(bitable, already)
        (OUT / "mcp_candidates.json").write_text(
            json.dumps(mcp_rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"[mcp] candidates={len(mcp_rows)}")
        rows = mcp_rows if args.mcp_only else (rows + mcp_rows)

    if not rows:
        write_status("NO_NEW", "no skill NEW and no MCP to add", {"count": 0})
        print("[NO_NEW] nothing to ingest")
        return 2

    items = [cand_to_item(r, bitable) for r in rows]
    snap = ingest_corpus(items)
    print(f"[corpus] added={snap['added']} touched={snap['updated_files']} total={snap['count']}")
    n_corpus = merge_feed(items)
    n_items = merge_items(items)
    print(f"[feed] corpus_new={n_corpus} items_new={n_items}")

    if snap["added"] == 0 and n_corpus == 0 and n_items == 0:
        write_status(
            "NO_NEW",
            "already in corpus and feed",
            {"candidates": len(items), "corpus_added": 0, "items_new": 0},
        )
        print("[NO_NEW] already present")
        return 2

    if cand_path.is_file():
        all_rows = json.loads(cand_path.read_text(encoding="utf-8"))
        ingested = {it["full_name"].lower() for it in items}
        for r in all_rows:
            if r.get("full_name", "").lower() in ingested and r.get("feed") == "NEW":
                r["feed"] = "ITEMS"
        cand_path.write_text(json.dumps(all_rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    write_status(
        "UPDATED",
        f"ingested {len(items)}; corpus+{snap['added']}; items+{n_items}",
        {
            "candidates": len(items),
            "corpus_added": snap["added"],
            "corpus_feed_new": n_corpus,
            "items_new": n_items,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
