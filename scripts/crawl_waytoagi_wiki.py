#!/usr/bin/env python3
"""Crawl the WaytoAGI Feishu wiki space, extract GitHub repos, push the bitable底表.

分层：底表求全求准（不论是否 skill）。失败必须通知（exit 1）。

用法（skill-feed 仓库根）:
  python scripts/crawl_waytoagi_wiki.py --walk-only
  python scripts/crawl_waytoagi_wiki.py --fetch --push-bitable
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from export_to_bitable import lark_bin, run_lark  # noqa: E402

HOME = Path.home()
DATA = HOME / ".skill-feed"
OUT = DATA / "bitable_export" / "waytoagi_wiki"
TARGET = DATA / "bitable_export" / "target.json"
CORPUS = DATA / "corpus" / "waytoagi"

SPACE_ID = "7226178700923011075"
GH_RE = re.compile(
    r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.I,
)
SKIP_OWNERS = {"topics", "settings", "orgs", "marketplace", "features", "pricing", "about", "login", "apps"}
SKIP_REPOS = {"issues", "pulls", "wiki", "pulse", "actions", "security", "projects"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lark_text(args: list[str], timeout: int = 60) -> str:
    env = {
        **dict(__import__("os").environ),
        "LARKSUITE_CLI_NO_UPDATE_NOTIFIER": "1",
        "LARKSUITE_CLI_NO_SKILLS_NOTIFIER": "1",
        "PYTHONUNBUFFERED": "1",
    }
    bin_path = lark_bin()
    proc = subprocess.run(
        [bin_path, *args],
        capture_output=True,
        env=env,
        timeout=timeout,
        shell=(str(bin_path).lower().endswith(".cmd")),
    )
    raw = proc.stdout or b""
    if isinstance(raw, str):
        return raw
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw.count(b"\x00") > 20:
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def _decode(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw.count(b"\x00") > 20:
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def list_nodes(parent: str | None = None) -> list[dict]:
    """Paginate with page-size 50. Avoid --page-limit 0 (hangs on Windows)."""
    rows: list[dict] = []
    page_token = ""
    for _ in range(40):
        args = [
            "wiki",
            "+node-list",
            "--as",
            "user",
            "--space-id",
            SPACE_ID,
            "--page-size",
            "50",
            "--format",
            "csv",
        ]
        if parent:
            args.extend(["--parent-node-token", parent])
        if page_token:
            args.extend(["--page-token", page_token])
        text = _lark_text(args)
        idx = text.find("has_child,")
        if idx < 0:
            idx = text.find("node_token,")
        if idx < 0:
            break
        chunk = list(csv.DictReader(io.StringIO(text[idx:])))
        for r in chunk:
            if not r.get("node_token"):
                continue
            rows.append(
                {
                    "has_child": str(r.get("has_child") or "").lower() == "true",
                    "node_token": (r.get("node_token") or "").strip(),
                    "obj_token": (r.get("obj_token") or "").strip(),
                    "obj_type": (r.get("obj_type") or "").strip(),
                    "title": (r.get("title") or "").strip(),
                    "parent": (r.get("parent_node_token") or parent or "").strip(),
                }
            )
        if len(chunk) < 50:
            break
        # csv 无 token；满页再要一页会重复。满 50 时改走 json has_more。
        js = _lark_text(
            [
                "wiki",
                "+node-list",
                "--as",
                "user",
                "--space-id",
                SPACE_ID,
                "--page-size",
                "50",
                "--format",
                "json",
                *(["--parent-node-token", parent] if parent else []),
                *(["--page-token", page_token] if page_token else []),
            ]
        )
        try:
            data = json.loads(js[js.find("{") :], strict=False)
        except json.JSONDecodeError:
            break
        page_token = (data.get("data") or {}).get("page_token") or ""
        if not (data.get("data") or {}).get("has_more"):
            break
        if not page_token:
            break
    return rows


def walk_tree() -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    queue: list[str | None] = [None]
    while queue:
        parent = queue.pop(0)
        try:
            nodes = list_nodes(parent)
        except Exception as e:  # noqa: BLE001
            print(f"[walk] FAIL parent={parent}: {e}")
            continue
        print(f"[walk] parent={parent or 'ROOT'} +{len(nodes)}", flush=True)
        for n in nodes:
            tok = n["node_token"]
            if tok in seen:
                continue
            seen.add(tok)
            out.append(n)
            if n["has_child"]:
                queue.append(tok)
        time.sleep(0.15)
    return out


def fetch_doc(url_or_token: str) -> str:
    return _lark_text(
        ["docs", "+fetch", "--as", "user", "--doc", url_or_token, "--format", "plain"],
        timeout=90,
    )


def extract_repos(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for m in GH_RE.finditer(text or ""):
        owner, repo = m.group(1), m.group(2)
        repo = repo.rstrip(".,);\"'")
        if repo.endswith(".git"):
            repo = repo[:-4]
        if owner.lower() in SKIP_OWNERS or repo.lower() in SKIP_REPOS:
            continue
        if owner.startswith("."):
            continue
        fn = f"{owner}/{repo}"
        key = fn.lower()
        if key in seen:
            continue
        seen.add(key)
        found.append(fn)
    return found


def gh_api_repo(full_name: str) -> dict | None:
    p = subprocess.run(["gh", "api", f"repos/{full_name}"], capture_output=True)
    if p.returncode != 0:
        return None
    return json.loads(p.stdout.decode("utf-8", errors="replace"))


def guess_kind(fn: str, desc: str) -> tuple[str, str]:
    blob = f"{fn} {desc}".lower()
    if "skill" in blob or "/skills" in blob:
        return "skill", "开发"
    if "mcp" in blob:
        return "mcp", "开发"
    if "agent" in blob:
        return "agent", "开发"
    if any(x in blob for x in ("awesome", "list")):
        return "oss", "研究"
    return "oss", "其他"


def to_bitable_row(meta: dict, wiki_token: str, wiki_title: str) -> dict:
    fn = meta["full_name"]
    kind, cat = guess_kind(fn, meta.get("description") or "")
    wiki_url = f"https://waytoagi.feishu.cn/wiki/{wiki_token}" if wiki_token else ""
    kws = ["WaytoAGI", "wiki-crawl", kind, wiki_title, wiki_url]
    return {
        "名称": (meta.get("name") or fn.split("/")[-1])[:200],
        "仓库全名": fn,
        "来源": "知识库",
        "发布人": meta.get("owner", {}).get("login") if isinstance(meta.get("owner"), dict) else fn.split("/")[0],
        "发布时间": (meta.get("pushed_at") or "")[:16],
        "GitHub链接": meta.get("html_url") or f"https://github.com/{fn}",
        "分类": cat,
        "二级分类": f"WaytoAGI · {kind}",
        "关键词": " · ".join(x for x in kws if x)[:200],
        "评星": int(meta.get("stargazers_count") or 0),
        "描述": (meta.get("description") or wiki_title or "")[:500],
        "收录时间": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"),
        "数据池": "知识库",
    }


def _add_names_from_rows(names: set[str], rows) -> None:
    if not isinstance(rows, list):
        return
    for r in rows:
        if not isinstance(r, dict):
            continue
        fn = (r.get("仓库全名") or r.get("full_name") or "").lower()
        if fn:
            names.add(fn)


def load_existing_names() -> set[str]:
    names: set[str] = set()
    dirs = [OUT, DATA / "bitable_export" / "waytoagi"]
    files: list[Path] = []
    for d in dirs:
        if not d.is_dir():
            continue
        files.extend(d.glob("preview.json"))
        files.extend(d.glob("*batch*.json"))
    pushed = OUT / "pushed_names.json"
    if pushed.is_file():
        try:
            data = json.loads(pushed.read_text(encoding="utf-8"))
            if isinstance(data, list):
                names.update(str(x).lower() for x in data)
        except json.JSONDecodeError:
            pass
    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and "create_records" in data:
            _add_names_from_rows(names, data.get("create_records"))
        else:
            _add_names_from_rows(names, data)
    return names


def push_rows(rows: list[dict]) -> None:
    if not rows:
        print("[bitable] nothing new to push")
        return
    OUT.mkdir(parents=True, exist_ok=True)
    target = json.loads(TARGET.read_text(encoding="utf-8"))
    bt, tid = target["base_token"], target["table_id"]
    # Feishu batch-create typically caps ~500; we chunk 80.
    # Continue numbering so later waves do not overwrite earlier batches.
    used = []
    for p in OUT.glob("batch_*.json"):
        try:
            used.append(int(p.stem.split("_")[-1]))
        except ValueError:
            continue
    start = (max(used) + 1) if used else 1
    for i in range(0, len(rows), 80):
        chunk = rows[i : i + 80]
        batch = OUT / f"batch_{start + i // 80:03d}.json"
        batch.write_text(
            json.dumps({"create_records": chunk}, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[bitable] push {len(chunk)} → {batch.name}")
        run_lark(
            [
                "base",
                "+record-batch-create",
                "--as",
                "user",
                "--base-token",
                bt,
                "--table-id",
                tid,
                "--json",
                f"@{batch.name}",
            ],
            cwd=OUT,
        )
    print(f"[bitable] done → https://trip.larkenterprise.com/base/{bt}")
    save_pushed_names(load_existing_names() | {r["仓库全名"].lower() for r in rows if r.get("仓库全名")})


def save_pushed_names(names: set[str]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "pushed_names.json").write_text(
        json.dumps(sorted(names), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def list_bitable_names() -> set[str]:
    """Read 仓库全名 from the Feishu 底表 (paginated; records go to --output)."""
    target = json.loads(TARGET.read_text(encoding="utf-8"))
    bt, tid = target["base_token"], target["table_id"]
    names: set[str] = set()
    offset = 0
    OUT.mkdir(parents=True, exist_ok=True)
    for page in range(1, 41):
        out = OUT / f"bitable_names_{page:03d}.ndjson"
        run_lark(
            [
                "base",
                "+record-list",
                "--as",
                "user",
                "--base-token",
                bt,
                "--table-id",
                tid,
                "--format",
                "ndjson",
                "--output",
                out.name,
                "--overwrite",
                "--minimal-stdout",
                "--limit",
                "500",
                "--offset",
                str(offset),
            ],
            cwd=OUT,
        )
        rows = 0
        if out.is_file():
            text = out.read_text(encoding="utf-8-sig", errors="replace")
            if "\x00" in text[:200]:
                text = out.read_bytes().decode("utf-16", errors="replace")
            for line in text.splitlines():
                raw = line.strip()
                if not raw.startswith("{"):
                    continue
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                fields = rec.get("fields") or rec
                fn = (fields.get("仓库全名") or "").strip()
                if fn:
                    names.add(fn.lower())
                rows += 1
        if rows < 500:
            break
        offset += rows
    return names


def verify_and_push(hits: dict, push: bool) -> tuple[int, int, list[str]]:
    existing = load_existing_names()
    rows: list[dict] = []
    miss: list[str] = []
    for rec in hits.values():
        fn = rec["full_name"]
        if fn.lower() in existing:
            continue
        meta = gh_api_repo(fn)
        if not meta:
            miss.append(fn)
            continue
        wiki = rec["wikis"][0] if rec["wikis"] else ""
        title = rec["titles"][0] if rec["titles"] else ""
        rows.append(to_bitable_row(meta, wiki, title))
        time.sleep(0.05)

    (OUT / "preview.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    miss_path = OUT / "miss.json"
    old_miss: list[str] = []
    if miss_path.is_file():
        try:
            prev = json.loads(miss_path.read_text(encoding="utf-8"))
            if isinstance(prev, list):
                old_miss = [str(x) for x in prev]
        except json.JSONDecodeError:
            pass
    merged_miss = list(dict.fromkeys(old_miss + miss))
    miss_path.write_text(json.dumps(merged_miss, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[gh] new_ok={len(rows)} miss={len(miss)} already={len(existing)}")

    if push:
        push_rows(rows)
    return len(rows), len(existing), miss


def write_status(status: str, detail: str, extra: dict) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": status,
        "checked_at": _now(),
        "detail": detail,
        "must_notify": status != "UPDATED",
        **extra,
    }
    (OUT / "latest-crawl-status.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if status != "UPDATED":
        (OUT / "CRAWL_ALERT.md").write_text(
            f"# WaytoAGI wiki crawl alert\n\n- status: **{status}**\n- {detail}\n\n"
            "必须用简体中文通知用户，禁止说刷新成功。\n",
            encoding="utf-8",
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--walk-only", action="store_true")
    ap.add_argument("--fetch", action="store_true")
    ap.add_argument("--push-bitable", action="store_true")
    ap.add_argument(
        "--verify-push",
        action="store_true",
        help="skip fetch; gh-check extracted_repos and push new rows",
    )
    ap.add_argument(
        "--sync-bitable-names",
        action="store_true",
        help="pull 仓库全名 from Feishu into pushed_names.json before dedupe",
    )
    ap.add_argument("--limit", type=int, default=0, help="max docs to fetch (0=all)")
    ap.add_argument(
        "--title-re",
        default="",
        help="only fetch docx whose title matches this regex (case-insensitive)",
    )
    args = ap.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    CORPUS.mkdir(parents=True, exist_ok=True)

    if args.sync_bitable_names:
        remote = list_bitable_names()
        merged = load_existing_names() | remote
        save_pushed_names(merged)
        print(f"[sync] bitable={len(remote)} merged_existing={len(merged)}")

    if args.verify_push:
        extracted_path = OUT / "extracted_repos.json"
        if not extracted_path.is_file():
            write_status("FETCH_FAILED", "no extracted_repos.json", {})
            print("[FAIL] missing extracted_repos.json")
            return 1
        hits = json.loads(extracted_path.read_text(encoding="utf-8"))
        try:
            new_ok, already, miss = verify_and_push(hits, args.push_bitable)
        except Exception as e:  # noqa: BLE001
            write_status("PUSH_FAILED", str(e), {"repos": len(hits)})
            print(f"[FAIL] bitable: {e}")
            return 1
        if not hits:
            write_status("FETCH_FAILED", "no github extracted", {"repos": 0})
            return 1
        write_status(
            "UPDATED" if new_ok else "NO_NEW",
            f"verify-push repos={len(hits)} new_rows={new_ok} miss={len(miss)}",
            {"repos": len(hits), "new_rows": new_ok, "miss": len(miss), "already": already},
        )
        return 0 if (new_ok or already) else 1

    tree_path = OUT / "wiki_tree.json"
    if tree_path.is_file() and not args.walk_only:
        nodes = json.loads(tree_path.read_text(encoding="utf-8"))
        print(f"[walk] reuse {len(nodes)} nodes from {tree_path}")
    else:
        nodes = walk_tree()
        tree_path.write_text(json.dumps(nodes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[walk] total nodes={len(nodes)}")

    if args.walk_only:
        kinds: dict[str, int] = {}
        for n in nodes:
            kinds[n["obj_type"]] = kinds.get(n["obj_type"], 0) + 1
        print("[walk] by type", kinds)
        write_status("WALKED", f"nodes={len(nodes)}", {"nodes": len(nodes), "by_type": kinds})
        return 0 if nodes else 1

    if not args.fetch:
        print("pass --fetch to extract GitHub from docs")
        return 0

    docs = [n for n in nodes if n.get("obj_type") == "docx"]
    if args.title_re:
        cre = re.compile(args.title_re, re.I)
        docs = [n for n in docs if cre.search(n.get("title") or "")]
        print(f"[fetch] title-re kept {len(docs)}")

    def _title_score(n: dict) -> int:
        t = n.get("title") or ""
        tl = t.lower()
        s = 0
        if any(x in t for x in ("宝库", "大全", "清单", "合集", "hub")):
            s += 10
        if "开源" in t:
            s += 6
        if "github" in tl:
            s += 6
        if any(x in t for x in ("十佳", "精选", "推荐")):
            s += 4
        if "skill" in tl:
            s += 2
        return -s

    docs.sort(key=_title_score)
    fetched_path = OUT / "fetched_tokens.json"
    fetched: set[str] = set()
    if fetched_path.is_file():
        try:
            fetched = set(json.loads(fetched_path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            fetched = set()
    before = len(docs)
    docs = [n for n in docs if n.get("node_token") not in fetched]
    print(f"[fetch] skip already-fetched {before - len(docs)}, remain {len(docs)}")
    if args.limit:
        docs = docs[: args.limit]
    print(f"[fetch] docs={len(docs)}")

    hits: dict[str, dict] = {}
    extracted_path = OUT / "extracted_repos.json"
    if extracted_path.is_file():
        try:
            hits = json.loads(extracted_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            hits = {}
    failed_docs = 0
    for i, n in enumerate(docs, 1):
        url = f"https://waytoagi.feishu.cn/wiki/{n['node_token']}"
        try:
            text = fetch_doc(url)
        except Exception as e:  # noqa: BLE001
            print(f"[fetch] FAIL {n['node_token']}: {e}")
            failed_docs += 1
            continue
        repos = extract_repos(text)
        if repos:
            print(f"[{i}/{len(docs)}] {(n.get('title') or '')[:40]} → {len(repos)} repos")
        for fn in repos:
            rec = hits.setdefault(
                fn.lower(),
                {"full_name": fn, "wikis": [], "titles": []},
            )
            rec["wikis"].append(n["node_token"])
            rec["titles"].append(n.get("title") or "")
        fetched.add(n["node_token"])
        if i % 20 == 0:
            fetched_path.write_text(json.dumps(sorted(fetched), ensure_ascii=False), encoding="utf-8")
            extracted_path.write_text(json.dumps(hits, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"[fetch] progress {i}/{len(docs)} unique_repos={len(hits)}")
        time.sleep(0.2)

    fetched_path.write_text(json.dumps(sorted(fetched), ensure_ascii=False), encoding="utf-8")
    extracted_path.write_text(json.dumps(hits, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[extract] unique repos={len(hits)} failed_docs={failed_docs}")

    try:
        new_ok, already, miss = verify_and_push(hits, args.push_bitable)
    except Exception as e:  # noqa: BLE001
        write_status("PUSH_FAILED", str(e), {"new": 0, "miss": []})
        print(f"[FAIL] bitable: {e}")
        return 1

    if not hits:
        write_status("FETCH_FAILED", "no github extracted", {"docs": len(docs), "failed_docs": failed_docs})
        return 1

    write_status(
        "UPDATED" if new_ok else "NO_NEW",
        f"docs={len(docs)} repos={len(hits)} new_rows={new_ok} miss={len(miss)}",
        {
            "docs": len(docs),
            "repos": len(hits),
            "new_rows": new_ok,
            "miss": len(miss),
            "failed_docs": failed_docs,
            "already": already,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
