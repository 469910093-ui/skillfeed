"""离线知识库：增量写入 ~/.skill-feed/corpus/。"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import hellogithub
import scene

CORPUS_DIRNAME = "corpus"
INDEX_NAME = "index.jsonl"
META_NAME = "meta.json"


def corpus_root(data_dir: Path) -> Path:
    return data_dir / CORPUS_DIRNAME


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_key(full_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._/-]+", "-", full_name).strip("/")


def _load_index_keys(index_path: Path) -> set[str]:
    keys: set[str] = set()
    if not index_path.exists():
        return keys
    try:
        for line in index_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            k = obj.get("id") or obj.get("full_name")
            if k:
                keys.add(str(k))
    except OSError:
        pass
    return keys


def _append_index(index_path: Path, rows: Iterable[dict]) -> int:
    index_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with index_path.open("a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n


def ingest_hellogithub(
    data_dir: Path,
    *,
    hg_repo: Optional[Path] = None,
    max_issues: int = 0,
    copy_issues: bool = True,
) -> dict:
    """
    将 HelloGitHub 全刊（或近 N 期）规范化入库。
    只增不删：已存在 id 跳过。
    """
    root = corpus_root(data_dir)
    hg_dir = root / "hellogithub"
    issues_dir = hg_dir / "issues"
    items_dir = hg_dir / "items"
    index_path = root / INDEX_NAME
    root.mkdir(parents=True, exist_ok=True)
    items_dir.mkdir(parents=True, exist_ok=True)
    if copy_issues:
        issues_dir.mkdir(parents=True, exist_ok=True)

    repo = hg_repo or hellogithub.resolve_repo()
    existing = _load_index_keys(index_path)
    items = hellogithub.load_items(repo, max_issues=max_issues)
    added = 0
    skipped = 0
    new_rows: list[dict] = []

    for it in items:
        issue = int(it.get("issue") or 0)
        fn = it.get("full_name") or ""
        cid = f"hg:{issue}:{fn}"
        if cid in existing:
            skipped += 1
            continue

        # 复制期文件（按期去重）
        if copy_issues and it.get("issue_file"):
            src = Path(it["issue_file"])
            dest = issues_dir / src.name
            if src.exists() and not dest.exists():
                try:
                    shutil.copy2(src, dest)
                except OSError:
                    pass

        kind = "skill" if it.get("hg_section") == "Skills" else "oss"
        if it.get("hg_section") == "人工智能":
            kind = "ai"
        row = {
            "id": cid,
            "full_name": fn,
            "name": it.get("name") or fn.split("/")[-1],
            "description": it.get("description") or "",
            "url": it.get("url") or f"https://github.com/{fn}",
            "source": "hellogithub",
            "kind": kind,
            "mode": "skills" if kind == "skill" else ("ai" if kind == "ai" else "oss"),
            "hg_section": it.get("hg_section") or "",
            "issue": issue,
            "stars": None,
            "stars_today": 0,
            "ingested_at": _now(),
            "from_corpus": True,
        }
        row = scene.apply_scene(row)
        # 单条 JSON 备份
        item_path = items_dir / f"{issue:03d}_{_safe_key(fn).replace('/', '__')}.json"
        try:
            item_path.write_text(json.dumps(row, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass
        new_rows.append(row)
        existing.add(cid)
        added += 1

    _append_index(index_path, new_rows)
    meta = {
        "updated_at": _now(),
        "hg_repo": str(repo),
        "added": added,
        "skipped": skipped,
        "total_indexed_approx": len(existing),
    }
    (root / META_NAME).write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return meta


def ingest_feed_skills(data_dir: Path, items: list[dict]) -> dict:
    """把本轮 Feed 过门禁的 skill 摘要写入 corpus（增量）。"""
    root = corpus_root(data_dir)
    gh_dir = root / "github" / "repos"
    index_path = root / INDEX_NAME
    root.mkdir(parents=True, exist_ok=True)
    existing = _load_index_keys(index_path)
    added = 0
    new_rows: list[dict] = []
    for it in items:
        fn = it.get("full_name") or ""
        if not fn:
            continue
        cid = f"gh:{fn}"
        if cid in existing:
            continue
        owner, repo = fn.split("/", 1)
        dest = gh_dir / owner / repo
        dest.mkdir(parents=True, exist_ok=True)
        snap = {
            "id": cid,
            "full_name": fn,
            "name": it.get("name") or repo,
            "description": it.get("description") or "",
            "url": it.get("url") or f"https://github.com/{fn}",
            "source": it.get("source") or "github.com/trending",
            "kind": "skill",
            "mode": "skills",
            "hg_section": it.get("hg_section") or "",
            "skill_path": it.get("skill_path") or "",
            "stars": it.get("stars"),
            "stars_today": it.get("stars_today") or 0,
            "scene": it.get("scene"),
            "scene_label": it.get("scene_label"),
            "body_preview": (it.get("body_preview") or "")[:1200],
            "ingested_at": _now(),
            "from_corpus": True,
        }
        if not snap.get("scene"):
            snap = scene.apply_scene(snap)
        try:
            (dest / "meta.json").write_text(
                json.dumps(snap, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
            )
            if it.get("body_preview"):
                (dest / "SKILL.preview.md").write_text(
                    str(it.get("body_preview")), encoding="utf-8",
                )
        except OSError:
            pass
        new_rows.append(snap)
        existing.add(cid)
        added += 1
    _append_index(index_path, new_rows)
    return {"added": added, "skipped": len(items) - added}


def load_corpus_items(
    data_dir: Path,
    *,
    limit: int = 200,
    mode: str = "",
    scene_id: str = "",
    hg_section: str = "",
    skill_priority: bool = False,
) -> list[dict]:
    """
    从 index.jsonl 取条目。
    默认按「期号/写入」新鲜度排序；skill_priority 时 Skills/skill 优先灌满。
    """
    index_path = corpus_root(data_dir) / INDEX_NAME
    if not index_path.exists():
        return []
    try:
        lines = index_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    scored: list[tuple[int, int, dict]] = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        kind = obj.get("kind") or "oss"
        sec = obj.get("hg_section") or ""
        if mode == "skills" and kind != "skill":
            continue
        if mode == "oss" and kind == "skill":
            continue
        if mode == "ai" and kind not in ("ai", "skill") and sec != "人工智能":
            continue
        if scene_id and scene_id != "all" and obj.get("scene") != scene_id:
            continue
        if hg_section and hg_section != "all":
            if hg_section.lower() not in sec.lower() and not sec.lower().startswith(hg_section.lower()):
                continue
        obj.setdefault("from_corpus", True)
        issue = int(obj.get("issue") or 0)
        # 新鲜度：期号优先，其次文件中靠前（全量 ingest 时新期在前）
        fresh = issue * 10_000 + max(0, 1_000_000 - i)
        pri = 0
        if skill_priority and (kind == "skill" or sec == "Skills"):
            pri = 1_000_000_000
        scored.append((pri + fresh, i, obj))

    scored.sort(key=lambda x: -x[0])
    return [obj for _, _, obj in scored[:limit]]


def load_skill_candidates(data_dir: Path, *, limit: int = 80) -> list[dict]:
    """专门拉 skill / HelloGitHub Skills 线索。"""
    return load_corpus_items(data_dir, limit=limit, skill_priority=True)


def attach_body_previews(data_dir: Path, items: list[dict]) -> list[dict]:
    """从 corpus/github/repos/*/meta.json 或 SKILL.preview.md 回填正文预览。"""
    root = corpus_root(data_dir) / "github" / "repos"
    out: list[dict] = []
    for it in items:
        row = dict(it)
        if (row.get("body_preview") or "").strip():
            out.append(row)
            continue
        fn = row.get("full_name") or ""
        if "/" not in fn:
            out.append(row)
            continue
        owner, repo = fn.split("/", 1)
        dest = root / owner / repo
        bp = ""
        meta_p = dest / "meta.json"
        if meta_p.exists():
            try:
                meta = json.loads(meta_p.read_text(encoding="utf-8"))
                bp = (meta.get("body_preview") or "").strip()
            except (OSError, json.JSONDecodeError):
                bp = ""
        if not bp:
            prev_p = dest / "SKILL.preview.md"
            if prev_p.exists():
                try:
                    bp = prev_p.read_text(encoding="utf-8").strip()
                except OSError:
                    bp = ""
        if bp:
            row["body_preview"] = bp[:1200]
        out.append(row)
    return out
