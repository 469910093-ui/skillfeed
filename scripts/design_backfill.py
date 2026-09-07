"""强制探测产品设计相关种子仓，合并进本机 feed.json 并重建 HTML。"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import catalog_sources  # noqa: E402
import feed_dashboard  # noqa: E402
import feed_pack  # noqa: E402
import scene  # noqa: E402
import skill_detect  # noqa: E402

DATA = Path.home() / ".skill-feed"
UA = "skill-feed/0.3 (+local; design-backfill)"
INTENT = "产品设计"


def main() -> int:
    force = list(catalog_sources.FORCE_PROBE_REPOS)
    print(f"[design-backfill] force repos={len(force)}")
    enriched: list[dict] = []
    for fn in force:
        row = {
            "full_name": fn,
            "description": "agent skills / design skills",
            "stars": None,
            "url": f"https://github.com/{fn}",
            "source": "catalog",
            "kind": "skill",
            "language": "",
            "stars_today": 0,
        }
        try:
            items = skill_detect.enrich_repo_multi(row, UA, always_probe=True, max_skills=6)
        except Exception as e:  # noqa: BLE001
            print(f"[design-backfill] ERR {fn}: {e}")
            continue
        for it in items:
            # 清掉旧 scene 字段，强制按最新规则重打
            for k in ("scene", "scene_label", "scene_l2", "scene_l2_label", "scene_why"):
                it.pop(k, None)
            it = scene.apply_scene(it)
            enriched.append(it)
            print(
                f"[hit] {it.get('full_name')} | {it.get('name')} | "
                f"{it.get('scene')}/{it.get('scene_l2')} | {(it.get('description') or '')[:70]}"
            )

    feed_path = DATA / "feed.json"
    old = (
        json.loads(feed_path.read_text(encoding="utf-8"))
        if feed_path.exists()
        else {"items": [], "corpus": [], "meta": {}, "gates": {}, "funnel": {}, "config": {}}
    )

    # 旧 live items：同仓若已有展开卡片则替换整仓
    expanded_repos = {e.get("full_name") for e in enriched}
    keep_live = [
        i
        for i in (old.get("items") or [])
        if not i.get("soft") and i.get("full_name") not in expanded_repos
    ]
    passed = enriched + keep_live

    meta = dict(old.get("meta") or {})
    meta["design_backfill_at"] = datetime.now(timezone.utc).isoformat()
    meta["intent"] = INTENT

    packed = feed_pack.pack_feed(
        passed=passed,
        corpus_rows=old.get("corpus") or [],
        meta=meta,
        gates_summary=old.get("gates") or {},
        funnel=old.get("funnel") or {},
        affinity={},
        intent=INTENT,
        config=old.get("config") or {},
        soft_limit=40,
    )
    feed_path.write_text(json.dumps(packed, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[design-backfill] wrote {feed_path} items={len(packed['items'])}")

    designish = [
        i
        for i in packed["items"]
        if i.get("scene") == "design"
        or any(
            k in (
                (i.get("name") or "")
                + " "
                + (i.get("description") or "")
                + " "
                + (i.get("skill_path") or "")
            ).lower()
            for k in ("design", "figma", "shadcn", "hallmark", "taste", "ui-ux")
        )
    ]
    print(f"[design-backfill] design-related={len(designish)}")
    for i in designish[:25]:
        print(
            f"  - {i.get('name')} | {i.get('full_name')} | "
            f"{i.get('skill_path')} | {i.get('scene_l2')}"
        )

    # 重建 HTML（含意图映射 JS）
    html = feed_dashboard.build_feed_html(packed, variant="full")
    lite = feed_dashboard.build_feed_html(packed, variant="lite")
    (DATA / "feed.html").write_text(html, encoding="utf-8")
    (DATA / "feed.lite.html").write_text(lite, encoding="utf-8")
    print("[design-backfill] wrote feed.html + feed.lite.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
