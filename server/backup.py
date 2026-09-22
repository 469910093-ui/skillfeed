"""把 SQLite 用户库打一份一致副本，并按份数轮转。

用户财产在 server.db，不在 GitHub。备份是第二份账本：误删、盘坏、
GitHub 登录挂了之后，至少还能从这里把户口和帖子找回来。
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def backup_sqlite(src: Path, dest_dir: Path, *, keep: int = 14) -> Path:
    src = Path(src)
    dest_dir = Path(dest_dir)
    if not src.is_file():
        raise FileNotFoundError(f"db not found: {src}")
    keep = max(1, min(90, int(keep)))
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = dest_dir / f"server-{stamp}.db"
    src_conn = sqlite3.connect(f"file:{src.as_posix()}?mode=ro", uri=True)
    try:
        dst_conn = sqlite3.connect(dest)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()
    prune_backups(dest_dir, keep=keep)
    return dest


def prune_backups(dest_dir: Path, *, keep: int) -> None:
    files = sorted(
        dest_dir.glob("server-*.db"),
        key=lambda p: p.name,
        reverse=True,
    )
    for old in files[keep:]:
        try:
            old.unlink()
        except OSError:
            pass


def backup_status(dest_dir: Path) -> dict[str, Any]:
    dest_dir = Path(dest_dir)
    files = sorted(dest_dir.glob("server-*.db"), key=lambda p: p.name, reverse=True)
    rows: list[dict[str, Any]] = []
    for f in files:
        try:
            st = f.stat()
            rows.append({
                "name": f.name,
                "bytes": int(st.st_size),
                "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            })
        except OSError:
            continue
    latest = files[0] if files else None
    return {
        "dir": str(dest_dir),
        "count": len(rows),
        "latest": latest.name if latest else "",
        "latest_bytes": int(rows[0]["bytes"]) if rows else 0,
        "files": rows,
    }
