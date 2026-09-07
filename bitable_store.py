"""译稿库：把 skills 与中英译稿落到飞书多维表格。

为什么要这一层：本地 `i18n/cards.jsonl` 是机器缓存，内容指纹一变就重译，而且
换机器、换 CI 就没了。多维表格提供两件本地缓存给不了的东西——

1. **人工验收**：状态标成「已验收」的行会被锁死，之后无论 SKILL.md 上游怎么改
   都不再调模型，译稿稳定，token 也不再重复烧。
2. **可编辑**：译稿写得不好可以直接在表里改，改完仍是「已验收」，下次 pull
   回来就是你改后的版本。

状态机：
    待审    机器刚译出来，未经人看。内容指纹变了会重译。
    已验收  人工确认过。锁定，永不重译（除非 --force）。
    需重译  人工判定译得不行，下次跑一定重译。

用法：
    python skillfeed.py bitable init --base-token TOKEN   # 建表（一次）
    python skillfeed.py bitable pull                      # 表 → 本地缓存
    python skillfeed.py bitable push                      # 本地译稿 → 表
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import i18n

TABLE_NAME = "译稿库"
TARGET_NAME = "bitable_target.json"
ROWS_NAME = "bitable_rows.json"

STATUS_PENDING = "待审"
STATUS_ACCEPTED = "已验收"
STATUS_REDO = "需重译"

# 表里一行 = 一个 skill 的译稿。列名即接口，改名要同步 _to_record / _from_record。
TABLE_FIELDS: list[dict] = [
    {"type": "text", "name": "唯一键"},
    {"type": "text", "name": "名称"},
    {"type": "text", "name": "仓库全名"},
    {"type": "text", "name": "skill路径"},
    {"type": "text", "name": "GitHub链接"},
    {
        "type": "select",
        "name": "状态",
        "options": [
            {"name": STATUS_PENDING},
            {"name": STATUS_ACCEPTED},
            {"name": STATUS_REDO},
        ],
    },
    {"type": "text", "name": "一句话_中"},
    {"type": "text", "name": "亮点_中"},
    {"type": "text", "name": "适合_中"},
    {"type": "text", "name": "一句话_英"},
    {"type": "text", "name": "亮点_英"},
    {"type": "text", "name": "适合_英"},
    {"type": "text", "name": "内容指纹"},
    {"type": "text", "name": "模型"},
    {"type": "text", "name": "更新时间"},
]

BATCH = 200

# ndjson 单次最多 2000 条，CLI 会硬校验（--limit 2001 直接报 invalid_argument）。
# 不显式传就默认 2000，一样封顶，所以必须翻页。
PAGE_LIMIT = 2000
# 2000 × 100 = 20 万行，远超译稿库可能的规模；纯粹用来兜住 CLI 行为异常时的死循环。
MAX_PAGES = 100


# --------------------------------------------------------------------------
# lark-cli 薄封装


def lark_bin() -> str:
    for name in ("lark-cli.cmd", "lark-cli", "lark-cli.exe"):
        p = shutil.which(name)
        if p:
            return p
    npm = Path(os.environ.get("APPDATA", "")) / "npm" / "lark-cli.cmd"
    if npm.is_file():
        return str(npm)
    raise RuntimeError("未找到 lark-cli，请先 npm i -g @larksuite/cli")


def run_lark(args: list[str], *, cwd: Optional[Path] = None) -> Any:
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
            f"lark-cli 失败 ({proc.returncode}): {proc.stderr or proc.stdout}"
        )
    raw = (proc.stdout or "").strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"_raw": raw}


# --------------------------------------------------------------------------
# 本地状态文件


def target_path(data_dir: Path) -> Path:
    return i18n.i18n_root(data_dir) / TARGET_NAME


def rows_path(data_dir: Path) -> Path:
    return i18n.i18n_root(data_dir) / ROWS_NAME


def load_target(data_dir: Path) -> dict:
    p = target_path(data_dir)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_target(data_dir: Path, base_token: str, table_id: str) -> None:
    p = target_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(
            {"base_token": base_token, "table_id": table_id, "table_name": TABLE_NAME},
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def load_rows(data_dir: Path) -> dict[str, dict]:
    """本地镜像：唯一键 → {record_id, status, hash}。push 靠它决定新建还是更新。"""
    p = rows_path(data_dir)
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_rows(data_dir: Path, rows: dict[str, dict]) -> None:
    p = rows_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------
# 记录 ↔ 缓存行 互转


def _join(vals: Any) -> str:
    if isinstance(vals, list):
        return "\n".join(str(v) for v in vals if str(v).strip())
    return str(vals or "")


def _split(text: str) -> list[str]:
    return [ln.strip() for ln in str(text or "").splitlines() if ln.strip()]


def _cell_text(val: Any) -> str:
    """多维表格文本单元格读回来可能是 str，也可能是 [{'text': ...}] 富文本段。"""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        return str(val.get("text") or val.get("name") or "")
    if isinstance(val, list):
        return "".join(_cell_text(x) for x in val)
    return str(val)


def _to_record(item: dict, fields: dict, *, hash_: str, model: str, status: str) -> dict:
    full_name = str(item.get("full_name") or "")
    path = str(item.get("skill_path") or "")
    url = str(item.get("url") or item.get("skill_url") or "")
    if not url and full_name:
        url = f"https://github.com/{full_name}"
    return {
        "唯一键": i18n.cache_key(item),
        "名称": str(item.get("name") or "")[:200],
        "仓库全名": full_name,
        "skill路径": path,
        "GitHub链接": url,
        "状态": status,
        "一句话_中": _join(fields.get("one_liner_zh")),
        "亮点_中": _join(fields.get("highlights_zh")),
        "适合_中": _join(fields.get("who_for_zh")),
        "一句话_英": _join(fields.get("one_liner_en")),
        "亮点_英": _join(fields.get("highlights_en")),
        "适合_英": _join(fields.get("who_for_en")),
        "内容指纹": hash_,
        "模型": model,
        "更新时间": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M"),
    }


def _from_record(rec: dict) -> Optional[dict]:
    """多维表格一行 → i18n 缓存行。字段不全的行直接跳过，不污染缓存。"""
    f = rec.get("fields") or rec
    key = _cell_text(f.get("唯一键")).strip()
    if not key:
        return None
    fields = {
        "one_liner_zh": _cell_text(f.get("一句话_中")).strip(),
        "one_liner_en": _cell_text(f.get("一句话_英")).strip(),
        "who_for_zh": _cell_text(f.get("适合_中")).strip(),
        "who_for_en": _cell_text(f.get("适合_英")).strip(),
        "highlights_zh": _split(_cell_text(f.get("亮点_中"))),
        "highlights_en": _split(_cell_text(f.get("亮点_英"))),
    }
    valid = i18n._valid_fields(fields)
    if not valid:
        return None
    status = _cell_text(f.get("状态")).strip() or STATUS_PENDING
    full_name = _cell_text(f.get("仓库全名")).strip()
    path = _cell_text(f.get("skill路径")).strip()
    return {
        "full_name": full_name or key.split("#", 1)[0],
        "skill_path": path,
        "hash": _cell_text(f.get("内容指纹")).strip(),
        "model": _cell_text(f.get("模型")).strip(),
        "status": status,
        # 已验收 = 锁定。i18n 见到 locked 就直接用，不再比对内容指纹。
        "locked": status == STATUS_ACCEPTED,
        "at": _cell_text(f.get("更新时间")).strip(),
        "fields": valid,
        "record_id": rec.get("record_id") or rec.get("id") or "",
    }


# --------------------------------------------------------------------------
# init / pull / push


def init_table(data_dir: Path, base_token: str) -> tuple[str, str]:
    """在已有 Base 里建译稿库表。已存在同名表就直接复用。"""
    listed = run_lark(
        ["base", "+table-list", "--as", "user", "--base-token", base_token, "--json"]
    )
    for t in _iter_tables(listed):
        if str(t.get("name") or "").strip() == TABLE_NAME:
            tid = str(t.get("table_id") or t.get("id") or "")
            if tid:
                save_target(data_dir, base_token, tid)
                return base_token, tid

    root = i18n.i18n_root(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    spec = root / "bitable_fields.json"
    spec.write_text(json.dumps(TABLE_FIELDS, ensure_ascii=False), encoding="utf-8")
    created = run_lark(
        [
            "base", "+table-create",
            "--as", "user",
            "--base-token", base_token,
            "--name", TABLE_NAME,
            "--fields", f"@{spec.name}",
            "--json",
        ],
        cwd=root,
    )
    tid = _dig_table_id(created)
    save_target(data_dir, base_token, tid)
    return base_token, tid


def _iter_tables(payload: Any) -> Iterable[dict]:
    if isinstance(payload, dict):
        data = payload.get("data") or payload
        items = data.get("items") or data.get("tables") or []
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    yield it
    elif isinstance(payload, list):
        for it in payload:
            if isinstance(it, dict):
                yield it


def _dig_table_id(payload: Any) -> str:
    if isinstance(payload, dict):
        data = payload.get("data") or payload
        for key in ("table_id", "id"):
            if data.get(key):
                return str(data[key])
        tbl = data.get("table") or {}
        for key in ("table_id", "id"):
            if tbl.get(key):
                return str(tbl[key])
    raise RuntimeError(f"无法解析 table_id: {payload}")


def _require_target(data_dir: Path) -> dict:
    tgt = load_target(data_dir)
    if not tgt.get("table_id"):
        raise RuntimeError("还没建译稿库，先跑 `skillfeed.py bitable init --base-token …`")
    return tgt


def _has_more(resp: Any) -> Optional[bool]:
    """--minimal-stdout 那段 JSON 里的 has_more。读不到就返回 None，绝不猜成 False。"""
    if isinstance(resp, dict) and isinstance(resp.get("has_more"), bool):
        return resp["has_more"]
    return None


def _page_count(resp: Any, fallback: int) -> int:
    """服务端这一页实际返回的条数。bool 是 int 的子类，要先挡掉再认整数。"""
    if isinstance(resp, dict):
        val = resp.get("records_count")
        if isinstance(val, int) and not isinstance(val, bool):
            return val
    return fallback


def _list_records(data_dir: Path) -> list[dict]:
    """把整张表读成记录列表。CLI 的 ndjson 一行一条，字段直接摊平在顶层。

    必须翻页：一次调用最多给 2000 条，剩下的要靠 --offset 接着取。这里宁可抛错
    也不能返回半张表——少读到的「已验收」行在 pull 看来等于不存在，缓存里就不会
    打 locked，下次 i18n 会把人工审校过的译稿重新调模型译一遍盖掉。
    """
    tgt = _require_target(data_dir)
    root = i18n.i18n_root(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    offset = 0
    for page in range(1, MAX_PAGES + 1):
        # 每页单独一个文件：--overwrite 只覆盖同名文件，共用一个名字会让后一页
        # 把前一页冲掉。
        out = f"bitable_pull_{page:03d}.ndjson"
        resp = run_lark(
            [
                "base", "+record-list",
                "--as", "user",
                "--base-token", str(tgt["base_token"]),
                "--table-id", str(tgt["table_id"]),
                "--format", "ndjson",
                "--output", out,
                "--overwrite",
                "--minimal-stdout",
                "--limit", str(PAGE_LIMIT),
                "--offset", str(offset),
            ],
            cwd=root,
        )
        rows = list(_read_ndjson(root / out))
        records.extend(rows)

        more = _has_more(resp)
        if more is False:
            return records
        if more is None:
            raise RuntimeError(
                f"读不到 +record-list 的 has_more（第 {page} 页，已取 {len(records)} 条），"
                f"无法确认整表是否取完。stdout: {resp!r}"
            )
        # offset 是记录偏移量而不是页码，要按服务端实际返回的条数推进。
        # 用解析成功的行数推进会在有坏行时错位，所以优先信 records_count。
        step = _page_count(resp, len(rows))
        if step <= 0:
            raise RuntimeError(
                f"+record-list 说 has_more 但第 {page} 页返回 0 条（offset={offset}），"
                "再翻也是空转，中止以免静默丢数据。"
            )
        offset += step
    raise RuntimeError(
        f"译稿库翻了 {MAX_PAGES} 页（约 {offset} 条）还没取完，疑似 CLI 翻页异常。"
        f"确认表规模正常后再调大 MAX_PAGES。"
    )


def pull(data_dir: Path) -> dict:
    """表 → 本地缓存。已验收的行写进缓存并打 locked。"""
    stats = {"remote": 0, "usable": 0, "accepted": 0, "redo": 0, "dupes": 0}
    cache_rows: list[dict] = []
    mirror = load_rows(data_dir)
    seen_keys: set[str] = set()
    for line in _list_records(data_dir):
        stats["remote"] += 1
        row = _from_record(line)
        if not row:
            continue
        stats["usable"] += 1
        dup_key = i18n.cache_key(
            {"full_name": row["full_name"], "skill_path": row["skill_path"]}
        )
        if dup_key in seen_keys:
            stats["dupes"] += 1
        seen_keys.add(dup_key)
        if row["status"] == STATUS_ACCEPTED:
            stats["accepted"] += 1
        elif row["status"] == STATUS_REDO:
            stats["redo"] += 1
            # 标了需重译就不要把旧译稿塞回缓存，否则下次照旧命中
            mirror[row["full_name"] + "#" + row["skill_path"]] = {
                "record_id": row["record_id"],
                "status": row["status"],
                "hash": "",
            }
            continue
        cache_rows.append(row)
        key = i18n.cache_key({"full_name": row["full_name"], "skill_path": row["skill_path"]})
        mirror[key] = {
            "record_id": row["record_id"],
            "status": row["status"],
            "hash": row["hash"],
        }
    if cache_rows:
        _append_cache(data_dir, cache_rows)
    save_rows(data_dir, mirror)
    return stats


def _read_ndjson(path: Path) -> Iterable[dict]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _append_cache(data_dir: Path, rows: list[dict]) -> None:
    p = i18n.cache_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def push(data_dir: Path, feed: dict, *, model: str = i18n.DEFAULT_MODEL) -> dict:
    """本地译稿 → 表。已验收的行绝不覆盖。"""
    tgt = _require_target(data_dir)
    mirror = load_rows(data_dir)
    stats = {
        "skipped_accepted": 0, "created": 0, "updated": 0,
        "no_fields": 0, "deduped": 0,
    }

    # 同一 skill 可能被多个源同时命中（github-search + catalog），feed 里就是两条。
    # 按唯一键收敛，否则表里会出现重复行。
    wanted: dict[str, dict] = {}
    for it in feed.get("items") or []:
        if not it.get("full_name"):
            continue
        fields = {k: it.get(k) for k in i18n.FIELDS if it.get(k)}
        if not i18n._valid_fields(fields):
            stats["no_fields"] += 1
            continue
        key = i18n.cache_key(it)
        if key in wanted:
            stats["deduped"] += 1
            continue
        wanted[key] = (it, fields)

    creates: list[dict] = []
    updates: list[dict] = []
    for key, (it, fields) in wanted.items():
        h = i18n.content_hash(it)
        known = mirror.get(key)
        rec = _to_record(it, fields, hash_=h, model=model, status=STATUS_PENDING)
        if not known:
            creates.append(rec)
            continue
        if known.get("status") == STATUS_ACCEPTED:
            stats["skipped_accepted"] += 1
            continue
        if known.get("hash") == h:
            continue
        rid = known.get("record_id")
        if rid:
            updates.append({"record_id": rid, "key": key, "fields": rec})
        else:
            creates.append(rec)

    root = i18n.i18n_root(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    if creates:
        stats["created"] = _batch_write(root, tgt, creates, mode="create", mirror=mirror)
    if updates:
        stats["updated"] = _batch_write(root, tgt, updates, mode="update", mirror=mirror)
    save_rows(data_dir, mirror)
    if creates:
        # batch-create 的返回结构不稳定，与其猜它，不如建完直接回读一次把
        # record_id 补齐——没有 id 就做不了后续增量更新。
        sync_record_ids(data_dir)
    return stats


def sync_record_ids(data_dir: Path) -> int:
    """回读整表，把 record_id 补进本地镜像。"""
    mirror = load_rows(data_dir)
    n = 0
    for rec in _list_records(data_dir):
        f = rec.get("fields") or rec
        key = _cell_text(f.get("唯一键")).strip()
        rid = str(rec.get("record_id") or rec.get("id") or "")
        if not key or not rid:
            continue
        row = mirror.setdefault(key, {})
        if row.get("record_id") != rid:
            row["record_id"] = rid
            n += 1
        row.setdefault("status", _cell_text(f.get("状态")).strip() or STATUS_PENDING)
        row.setdefault("hash", _cell_text(f.get("内容指纹")).strip())
    save_rows(data_dir, mirror)
    return n


def dedupe(data_dir: Path) -> dict:
    """删掉唯一键重复的行，每个键只留最后一条。"""
    by_key: dict[str, list[str]] = {}
    for rec in _list_records(data_dir):
        f = rec.get("fields") or rec
        key = _cell_text(f.get("唯一键")).strip()
        rid = str(rec.get("record_id") or rec.get("id") or "")
        if key and rid:
            by_key.setdefault(key, []).append(rid)
    victims = [rid for ids in by_key.values() if len(ids) > 1 for rid in ids[:-1]]
    if victims:
        tgt = _require_target(data_dir)
        for i in range(0, len(victims), BATCH):
            run_lark(
                [
                    "base", "+record-delete",
                    "--as", "user",
                    "--yes",  # CLI 把删记录标为高危写，必须显式确认
                    "--base-token", str(tgt["base_token"]),
                    "--table-id", str(tgt["table_id"]),
                    *sum((["--record-id", r] for r in victims[i : i + BATCH]), []),
                ]
            )
        sync_record_ids(data_dir)
    return {"keys": len(by_key), "deleted": len(victims)}


def _batch_write(
    root: Path, tgt: dict, payload: list[dict], *, mode: str, mirror: dict
) -> int:
    verb = "+record-batch-create" if mode == "create" else "+record-batch-update"
    done = 0
    for i in range(0, len(payload), BATCH):
        chunk = payload[i : i + BATCH]
        name = f"bitable_{mode}_{i // BATCH + 1:03d}.json"
        if mode == "create":
            body: dict = {"create_records": chunk}
        else:
            # batch-update 要的是「记录ID → 字段表」的映射，不是数组。
            body = {
                "update_records": {
                    str(r["record_id"]): _writable(r["fields"]) for r in chunk
                }
            }
        (root / name).write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
        run_lark(
            [
                "base", verb,
                "--as", "user",
                "--base-token", str(tgt["base_token"]),
                "--table-id", str(tgt["table_id"]),
                "--json", f"@{name}",
            ],
            cwd=root,
        )
        if mode == "create":
            for rec in chunk:
                key = str(rec.get("唯一键") or "")
                if key:
                    mirror[key] = {
                        "record_id": "",  # push 结束后由 sync_record_ids 补
                        "status": rec.get("状态") or STATUS_PENDING,
                        "hash": rec.get("内容指纹") or "",
                    }
        else:
            for rec in chunk:
                key = str(rec.get("key") or "")
                if key in mirror:
                    mirror[key]["hash"] = (rec.get("fields") or {}).get("内容指纹", "")
        done += len(chunk)
    return done


def _writable(fields: dict) -> dict:
    """单选字段写入要用数组形式，其余原样。"""
    out = dict(fields)
    if "状态" in out and not isinstance(out["状态"], list):
        out["状态"] = [out["状态"]]
    return out
