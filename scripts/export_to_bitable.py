#!/usr/bin/env python3
"""导出资源为飞书底表记录 JSON。

飞书表 = 全量底仓（不论是否 skill）。skill-feed Feed 是从表/本地语料再筛的子集。
--scope full：底表视角（全、准确）
--scope feed：只看当前信息流漏斗（勿与底表混为一谈）

用法:
  python scripts/export_to_bitable.py export [--out DIR] [--scope feed|full]
  python scripts/export_to_bitable.py push [--out DIR] [--base-token TOKEN] [--table-id ID]
  python scripts/export_to_bitable.py create-and-push [--out DIR]

默认读 ~/.skill-feed/feed.json + corpus/index.jsonl，去重后写 batch JSON 供 lark-cli 导入。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HOME = Path.home()
DATA_DIR = HOME / ".skill-feed"
FEED_JSON = DATA_DIR / "feed.json"
INDEX_JSONL = DATA_DIR / "corpus" / "index.jsonl"
CORPUS_PREVIEW = DATA_DIR / "corpus" / "github" / "repos"
DEFAULT_OUT = DATA_DIR / "bitable_export"

SOURCE_LABELS = {
    "github.com/trending": "Trending",
    "hellogithub": "HelloGitHub",
    "github-search": "GitHub Search",
    "catalog": "策展目录",
    "xiaohongshu": "小红书",
    "corpus": "知识库",
    "the-download": "The Download",
    "ugc": "用户上传",
}

SCENE_TO_CAT = {
    "设计与视觉": "设计",
    "工程开发": "开发",
    "Bug与质量": "运维",
    "数据与复盘": "数据",
    "内容创作": "内容",
    "协作办公": "协作",
    "研究与知识": "研究",
    "Agent工具链": "开发",
    "业务垂直": "业务",
    "其他": "其他",
}

TRANSLATION_RE = re.compile(
    r"翻译|translate|translation|i18n|本地化|localization|l10n|multilingual",
    re.I,
)

TABLE_FIELDS = [
    {"type": "text", "name": "名称"},
    {"type": "text", "name": "仓库全名"},
    {
        "type": "select",
        "name": "来源",
        "options": [{"name": v} for v in SOURCE_LABELS.values()],
    },
    {"type": "text", "name": "发布人"},
    {"type": "text", "name": "发布时间"},
    {"type": "text", "name": "GitHub链接"},
    {
        "type": "select",
        "name": "分类",
        "options": [
            {"name": x}
            for x in ["设计", "开发", "运维", "数据", "翻译", "内容", "协作", "研究", "业务", "其他"]
        ],
    },
    {"type": "text", "name": "二级分类"},
    {"type": "text", "name": "关键词"},
    {"type": "number", "name": "评星"},
    {"type": "text", "name": "描述"},
    {"type": "number", "name": "HelloGitHub期数"},
    {"type": "text", "name": "收录时间"},
    {
        "type": "select",
        "name": "数据池",
        "options": [{"name": "主Feed"}, {"name": "知识库"}],
    },
]


def extract_keywords(text: str) -> str:
    body = text or ""
    if body.lstrip().startswith("---"):
        parts = body.lstrip().split("---", 2)
        if len(parts) == 3:
            body = parts[2]
    heads = re.findall(r"^#{1,4}\s+(.+)$", body, re.M)
    bolds = re.findall(r"\*\*([^*\n]{2,30})\*\*", body)
    codes = re.findall(r"`([A-Za-z0-9_./\-]{3,40})`", body)
    out, seen = [], set()
    for t in heads + bolds + codes[:30]:
        t = re.sub(r"[#*`\\[\\]()]+", "", t).strip()
        if t and t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return " ".join(out)[:400]


def preview_path(full_name: str) -> Path | None:
    if not full_name or "/" not in full_name:
        return None
    owner, repo = full_name.split("/", 1)
    for sub in (repo, ""):
        base = CORPUS_PREVIEW / owner / sub if sub else CORPUS_PREVIEW / owner
        p = base / "SKILL.preview.md"
        if p.is_file():
            return p
    return None


def load_index() -> dict[str, dict]:
    rows: dict[str, dict] = {}
    if not INDEX_JSONL.is_file():
        return rows
    for line in INDEX_JSONL.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        fn = (obj.get("full_name") or "").strip()
        if fn:
            rows[fn] = obj
    return rows


def load_feed_pools() -> tuple[dict[str, dict], dict[str, dict]]:
    live, browse = {}, {}
    if not FEED_JSON.is_file():
        return live, browse
    data = json.loads(FEED_JSON.read_text(encoding="utf-8"))
    for it in data.get("items") or []:
        fn = (it.get("full_name") or "").strip()
        if fn:
            live[fn] = it
    for it in data.get("corpus") or []:
        fn = (it.get("full_name") or "").strip()
        if fn and fn not in browse:
            browse[fn] = it
    return live, browse


def merge_record(full_name: str, index: dict, live: dict, browse: dict) -> dict:
    """live > browse > index；保留 feed 中的真实 source。"""
    for pool in (live, browse, index):
        row = pool.get(full_name)
        if row:
            base = dict(row)
            break
    else:
        return {}
    for pool in (live, browse):
        r = pool.get(full_name)
        if not r:
            continue
        src = str(r.get("source") or "")
        if src and src not in ("corpus", "hellogithub"):
            base["source"] = src
            break
    return base


def classify(row: dict) -> str:
    scene = (row.get("scene_label") or "").strip()
    cat = SCENE_TO_CAT.get(scene, "其他")
    hay = " ".join(
        str(row.get(k) or "")
        for k in ("name", "description", "one_liner", "body_preview", "highlights")
    )
    if TRANSLATION_RE.search(hay):
        return "翻译"
    return cat


def publish_time(row: dict) -> str:
    issue = row.get("issue")
    if issue:
        return f"HelloGitHub 第{issue}期"
    ing = row.get("ingested_at") or row.get("fetched_at") or ""
    if ing:
        try:
            dt = datetime.fromisoformat(str(ing).replace("Z", "+00:00"))
            return dt.astimezone().strftime("%Y-%m-%d")
        except ValueError:
            return str(ing)[:10]
    return ""


def source_label(raw: str) -> str:
    return SOURCE_LABELS.get(raw or "", raw or "未知")


def keywords_for(row: dict, full_name: str) -> str:
    prev = preview_path(full_name)
    if prev:
        kw = extract_keywords(prev.read_text(encoding="utf-8", errors="replace"))
        if kw:
            return kw
    parts = [
        row.get("name") or "",
        row.get("description") or "",
        row.get("one_liner") or "",
        row.get("body_preview") or "",
        " ".join(row.get("highlights") or []) if isinstance(row.get("highlights"), list) else "",
    ]
    text = " ".join(p for p in parts if p).strip()
    kw = extract_keywords(text)
    if kw:
        return kw
    # 回退：描述前 120 字拆词
    desc = (row.get("description") or row.get("one_liner") or "")[:120]
    return desc


def to_bitable_row(full_name: str, row: dict, *, in_live: bool) -> dict:
    owner = (row.get("owner") or "").strip()
    if not owner and "/" in full_name:
        owner = full_name.split("/", 1)[0]
    url = (row.get("url") or row.get("skill_url") or f"https://github.com/{full_name}").strip()
    stars = row.get("stars")
    try:
        stars_num = int(stars) if stars is not None and stars != "" else None
    except (TypeError, ValueError):
        stars_num = None
    issue = row.get("issue")
    try:
        issue_num = int(issue) if issue is not None and issue != "" else None
    except (TypeError, ValueError):
        issue_num = None
    ing = row.get("ingested_at") or ""
    if ing:
        try:
            ing = datetime.fromisoformat(str(ing).replace("Z", "+00:00")).astimezone().strftime(
                "%Y-%m-%d %H:%M"
            )
        except ValueError:
            ing = str(ing)[:16]
    desc = (row.get("description") or row.get("one_liner") or "")[:500]
    out = {
        "名称": (row.get("name") or full_name.split("/")[-1])[:200],
        "仓库全名": full_name,
        "来源": source_label(str(row.get("source") or "")),
        "发布人": owner,
        "发布时间": publish_time(row),
        "GitHub链接": url,
        "分类": classify(row),
        "二级分类": (row.get("scene_l2_label") or row.get("hg_section") or "")[:100],
        "关键词": keywords_for(row, full_name),
        "描述": desc,
        "HelloGitHub期数": issue_num,
        "收录时间": ing,
        "数据池": "主Feed" if in_live else "知识库",
    }
    if stars_num is not None:
        out["评星"] = stars_num
    return out


def build_rows(*, scope: str = "feed") -> list[dict]:
    """scope: feed=主 Feed+知识库补货；full=含 HelloGitHub 全刊 index（慎用）。"""
    index = load_index()
    live, browse = load_feed_pools()
    if scope == "full":
        names = sorted(set(index) | set(live) | set(browse))
    else:
        names = sorted(set(live) | set(browse))
    rows = []
    for fn in names:
        merged = merge_record(fn, index, live, browse)
        if not merged:
            continue
        rows.append(to_bitable_row(fn, merged, in_live=fn in live))
    # 追加已审核通过的 UGC 帖子（来源=用户上传）
    rows.extend(_load_ugc_rows())
    return rows


def _load_ugc_rows() -> list[dict]:
    """从 server SQLite 读已审核通过的 UGC 帖子，转成底表记录格式。"""
    import sqlite3

    db = DATA_DIR / "server.db"
    if not db.is_file():
        return []
    rows: list[dict] = []
    try:
        conn = sqlite3.connect(str(db), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        posts = conn.execute(
            "SELECT * FROM posts WHERE status IN ('approved','published') ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    for p in posts:
        fn = p["full_name"] or ""
        if not fn:
            continue
        row = {
            "name": p["title"] or fn.split("/")[-1],
            "description": p["description"] or "",
            "one_liner": (p["description"] or "")[:140],
            "body_preview": p["description"] or "",
            "full_name": fn,
            "url": p["github_url"] or f"https://github.com/{fn}",
            "skill_url": p["github_url"] or f"https://github.com/{fn}",
            "source": "ugc",
            "owner": fn.split("/")[0] if "/" in fn else "",
            "stars": None,
            "scene": p["scene"] or "other",
            "scene_label": p["scene_label"] or "其他",
            "scene_l2_label": p["scene_l2_label"] or "",
            "ingested_at": p["created_at"] or "",
        }
        rows.append(to_bitable_row(fn, row, in_live=True))
    return rows


def write_batches(rows: list[dict], out_dir: Path, chunk: int = 200) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(rows),
        "chunk_size": chunk,
    }
    (out_dir / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    paths: list[Path] = []
    for i in range(0, len(rows), chunk):
        batch = rows[i : i + chunk]
        p = out_dir / f"batch_{i // chunk + 1:03d}.json"
        p.write_text(
            json.dumps({"create_records": batch}, ensure_ascii=False),
            encoding="utf-8",
        )
        paths.append(p)
    (out_dir / "all_records.json").write_text(
        json.dumps(rows, ensure_ascii=False), encoding="utf-8"
    )
    return paths


def lark_bin() -> str:
    for name in ("lark-cli.cmd", "lark-cli", "lark-cli.exe"):
        p = shutil.which(name)
        if p:
            return p
    npm = Path(os.environ.get("APPDATA", "")) / "npm" / "lark-cli.cmd"
    if npm.is_file():
        return str(npm)
    raise RuntimeError("未找到 lark-cli，请先 npm i -g @larksuite/cli 或确保在 PATH 中")


def run_lark(args: list[str], *, cwd: Path | None = None) -> dict:
    env = {
        **dict(os.environ),
        "LARKSUITE_CLI_NO_UPDATE_NOTIFIER": "1",
        "LARKSUITE_CLI_NO_SKILLS_NOTIFIER": "1",
    }
    cmd = [lark_bin(), *args]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        cwd=str(cwd) if cwd else None,
        shell=(os.name == "nt" and str(cmd[0]).lower().endswith(".cmd")),
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"lark-cli failed ({proc.returncode}): {proc.stderr or proc.stdout}"
        )
    raw = proc.stdout.strip()
    if not raw:
        return {}
    return json.loads(raw)


def _unwrap_created(created: dict) -> tuple[str, str]:
    data = created.get("data") or created
    base = data.get("base") or {}
    table = data.get("table") or {}
    base_token = (
        created.get("base_token")
        or data.get("base_token")
        or base.get("base_token")
        or base.get("app_token")
    )
    table_id = created.get("table_id") or data.get("table_id") or table.get("id")
    if base_token and table_id:
        return str(base_token), str(table_id)
    raise RuntimeError(f"无法解析 base_token/table_id: {created}")


def cmd_export(out_dir: Path, scope: str) -> int:
    rows = build_rows(scope=scope)
    paths = write_batches(rows, out_dir)
    print(f"[export] {len(rows)} 条 → {out_dir} ({len(paths)} 批)")
    return 0


def cmd_create_and_push(out_dir: Path, scope: str) -> int:
    rows = build_rows(scope=scope)
    paths = write_batches(rows, out_dir)
    ts = datetime.now().strftime("%Y%m%d")
    name = f"skill-feed 资源库 {ts}"
    fields_path = out_dir / "table_fields.json"
    fields_path.write_text(json.dumps(TABLE_FIELDS, ensure_ascii=False), encoding="utf-8")
    print(f"[create] Base: {name}")
    created = run_lark(
        [
            "base",
            "+base-create",
            "--as",
            "user",
            "--name",
            name,
            "--table-name",
            "资源清单",
            "--fields",
            "@table_fields.json",
            "--time-zone",
            "Asia/Shanghai",
        ],
        cwd=out_dir,
    )
    base_token, table_id = _unwrap_created(created)
    print(f"[create] base_token={base_token} table_id={table_id}")
    (out_dir / "target.json").write_text(
        json.dumps({"base_token": base_token, "table_id": table_id, "name": name}, indent=2),
        encoding="utf-8",
    )
    for i, p in enumerate(paths, 1):
        print(f"[push] batch {i}/{len(paths)} {p.name}")
        run_lark(
            [
                "base",
                "+record-batch-create",
                "--as",
                "user",
                "--base-token",
                base_token,
                "--table-id",
                table_id,
                "--json",
                f"@{p.name}",
            ],
            cwd=out_dir,
        )
    print(f"[done] {len(rows)} 条已写入「{name}」")
    return 0


def cmd_push(out_dir: Path, base_token: str, table_id: str) -> int:
    paths = sorted(out_dir.glob("batch_*.json"))
    if not paths:
        raise SystemExit(f"未找到 batch 文件: {out_dir}")
    for i, p in enumerate(paths, 1):
        print(f"[push] batch {i}/{len(paths)} {p.name}")
        run_lark(
            [
                "base",
                "+record-batch-create",
                "--as",
                "user",
                "--base-token",
                base_token,
                "--table-id",
                table_id,
                "--json",
                f"@{p.name}",
            ],
            cwd=out_dir,
        )
    print(f"[done] {len(paths)} 批已写入")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="skill-feed → 飞书多维表格")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_exp.add_argument("--scope", choices=("feed", "full"), default="feed")
    p_cap = sub.add_parser("create-and-push", help="建 Base 并导入")
    p_cap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p_cap.add_argument("--scope", choices=("feed", "full"), default="feed")
    p_push = sub.add_parser("push", help="向已有 Base 导入 batch")
    p_push.add_argument("--out", type=Path, default=DEFAULT_OUT)
    p_push.add_argument("--base-token", required=True)
    p_push.add_argument("--table-id", required=True)
    args = ap.parse_args()
    if args.cmd == "export":
        return cmd_export(args.out, args.scope)
    if args.cmd == "create-and-push":
        return cmd_create_and_push(args.out, args.scope)
    if args.cmd == "push":
        return cmd_push(args.out, args.base_token, args.table_id)
    return 1


if __name__ == "__main__":
    sys.exit(main())
