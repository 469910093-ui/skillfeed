"""SKILL.md 全文落盘：给意图搜索当正文索引用。

feed.json 只带 700 字的 body_preview（页面要轻），搜索却需要全文——触发词、
适用场景、多语说明常写在正文后半段。全文单独存在 `<data>/md/` 下，
不进 feed.json、不进页面脚本。

路径：`<root>/<owner>/<sha1(full_name|skill_path)[:16]>.md`
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Callable, Iterable, Optional

MD_MAX_CHARS = 20000


def md_root(data_dir: Path) -> Path:
    env = (os.environ.get("SKILLFEED_MD_DIR") or "").strip()
    if env:
        return Path(env).expanduser().resolve()
    return Path(data_dir) / "md"


def md_key(item: dict) -> str:
    fn = str(item.get("full_name") or "").strip().lower()
    path = str(item.get("skill_path") or "").strip()
    return hashlib.sha1(f"{fn}|{path}".encode("utf-8")).hexdigest()[:16]


def md_path(root: Path, item: dict) -> Optional[Path]:
    fn = str(item.get("full_name") or "").strip()
    if "/" not in fn:
        return None
    owner = fn.split("/", 1)[0].lower() or "_"
    return Path(root) / owner / f"{md_key(item)}.md"


def save_md(root: Path, item: dict, text: str) -> bool:
    path = md_path(root, item)
    if path is None or not (text or "").strip():
        return False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text[:MD_MAX_CHARS], encoding="utf-8")
    except OSError:
        return False
    return True


class MdLookup:
    """按条目取全文；按文件 mtime 缓存，服务端常驻进程里反复搜不重复读盘。"""

    def __init__(self, root: Path):
        self.root = Path(root)
        self._cache: dict[str, tuple[float, str]] = {}

    def __call__(self, item: dict) -> str:
        path = md_path(self.root, item)
        if path is None:
            return ""
        key = str(path)
        try:
            mtime = path.stat().st_mtime
        except OSError:
            self._cache.pop(key, None)
            return ""
        hit = self._cache.get(key)
        if hit and hit[0] == mtime:
            return hit[1]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        self._cache[key] = (mtime, text)
        return text

    def warm(self, items: Iterable[dict]) -> int:
        n = 0
        for it in items:
            if self(it):
                n += 1
        return n

    def has(self, item: dict) -> bool:
        path = md_path(self.root, item)
        return bool(path and path.is_file())


def backfill(
    items: Iterable[dict],
    root: Path,
    fetch: Callable[[str, str, str], Optional[str]],
    *,
    limit: int = 200,
    force: bool = False,
) -> dict:
    """给缺全文的条目补抓 SKILL.md。fetch(owner, repo, skill_path) → 文本或 None。

    同一 (仓, 路径) 只抓一次；失败计数如实返回，调用方负责告诉用户。
    """
    lookup = MdLookup(root)
    seen: set[str] = set()
    stats = {"fetched": 0, "skipped": 0, "failed": 0, "no_path": 0}
    for it in items:
        if stats["fetched"] + stats["failed"] >= limit:
            break
        fn = str(it.get("full_name") or "").strip()
        path = str(it.get("skill_path") or "").strip()
        if "/" not in fn or not path:
            stats["no_path"] += 1
            continue
        key = md_key(it)
        if key in seen:
            continue
        seen.add(key)
        if not force and lookup.has(it):
            stats["skipped"] += 1
            continue
        owner, repo = fn.split("/", 1)
        text = fetch(owner, repo, path)
        if text and save_md(root, it, text):
            stats["fetched"] += 1
        else:
            stats["failed"] += 1
    return stats
