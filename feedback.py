"""用户反馈落盘 feedback.jsonl。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VALID_ACTIONS = frozenset({
    "useful",
    "bad",
    "opened_github",
    "wrong_scene",
    "skip",
})


def feedback_path(data_dir: Path) -> Path:
    return data_dir / "feedback.jsonl"


def append_feedback(data_dir: Path, payload: dict[str, Any]) -> dict:
    action = (payload.get("action") or "").strip()
    if action not in VALID_ACTIONS:
        return {"ok": False, "error": f"invalid action; want one of {sorted(VALID_ACTIONS)}"}
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "full_name": (payload.get("full_name") or "").strip(),
        "source": payload.get("source") or "",
        "scene": payload.get("scene") or "",
        "scene_l2": payload.get("scene_l2") or "",
        "suggested_scene": payload.get("suggested_scene") or "",
        "note": (payload.get("note") or "")[:500],
        "from_corpus": bool(payload.get("from_corpus")),
    }
    path = feedback_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return {"ok": True, "row": row}


def summarize(data_dir: Path, limit: int = 50) -> dict:
    path = feedback_path(data_dir)
    if not path.exists():
        return {"ok": True, "total": 0, "by_action": {}, "recent": []}
    by: dict[str, int] = {}
    recent: list[dict] = []
    total = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {"ok": False, "error": "cannot read feedback.jsonl"}
    for line in lines:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        total += 1
        a = obj.get("action") or "?"
        by[a] = by.get(a, 0) + 1
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            recent.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(recent) >= limit:
            break
    return {"ok": True, "total": total, "by_action": by, "recent": recent}
