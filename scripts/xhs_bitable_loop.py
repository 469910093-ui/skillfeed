#!/usr/bin/env python3
"""小红书 CSV 原地 enrichment → GitHub 校验 → 飞书多维表格。

标准 loop（每次小红书新 CSV 后跑）:
  1. 读**原 CSV 文件** + connector 缓存，合并正文
  2. web-collection noteLink 补正文（local connector，限量）
  3. 抽取 GitHub 仓 → 实网校验 stars + SKILL.md
  4. **写回原 CSV**（不新建 CSV）并追加校验列
  5. 通过门禁的 skill 写入多维表格（来源=小红书）

用法:
  python scripts/xhs_bitable_loop.py run [--csv PATH ...] [--note-link-limit N]
  python scripts/xhs_bitable_loop.py audit-stars [--base-token T] [--table-id ID]
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import scene
import skill_detect
import xiaohongshu

from export_to_bitable import (  # noqa: E402
    classify,
    keywords_for,
    lark_bin,
    run_lark,
)

HOME = Path.home()
DATA_DIR = HOME / ".skill-feed"
DEFAULT_CSV_DIR = ROOT / "小红书搜集"
OUT_DIR = DATA_DIR / "xhs_loop"
TARGET_JSON = DATA_DIR / "bitable_export" / "target.json"
GIT_BASH = Path(r"C:\Program Files\Git\bin\bash.exe")
WEB_COLLECTION = HOME / ".codex" / "skills" / "web-collection"
BRIDGE_TOKEN = HOME / ".meixi-connector" / "bridge-admin-token.txt"
MIN_STARS_DEFAULT = 20

ENRICH_COLUMNS = ("提取GitHub仓", "校验状态", "评星", "是否通过门禁", "更新时间")


def load_cfg() -> dict:
    p = DATA_DIR / "config.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return json.loads((ROOT / "config_defaults.json").read_text(encoding="utf-8"))


def bridge_token() -> str:
    return BRIDGE_TOKEN.read_text(encoding="utf-8").strip()


def connector_get(path: str) -> dict:
    req = urllib.request.Request(
        f"http://127.0.0.1:19820{path}",
        headers={"x-connector-admin-token": bridge_token()},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def ensure_connector() -> bool:
    try:
        st = connector_get("/api/status")
        return bool(st.get("pluginConnected"))
    except Exception:
        exe = Path(r"D:\Users\yaowenliang\AppData\Local\Programs\Meixi Connector\bin\meixi-connector.exe")
        if exe.is_file():
            subprocess.Popen([str(exe)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(6)
            try:
                return bool(connector_get("/api/status").get("pluginConnected"))
            except Exception:
                return False
        return False


def note_key(url: str) -> str:
    u = (url or "").strip()
    m = re.search(r"/discovery/item/([a-f0-9]+)", u, re.I)
    if m:
        return m.group(1).lower()
    return u.split("?")[0].lower()


def find_latest_keyword_task() -> str | None:
    try:
        st = connector_get("/api/status")
    except Exception:
        return None
    for ps in st.get("platformStates") or []:
        if ps.get("platform") == "xiaohongshu" and ps.get("taskId"):
            tid = ps["taskId"]
            if "keywordSearch" in tid:
                return tid
    # 已知本机一次成功采集任务（80 条）
    known = "xiaohongshu-keywordSearch-1788324089995"
    try:
        task = connector_get(f"/api/tasks/{known}")
        if task.get("records"):
            return known
    except Exception:
        pass
    return None


def load_connector_index() -> dict[str, dict]:
    """url_key -> note dict。"""
    idx: dict[str, dict] = {}
    task_id = find_latest_keyword_task()
    if not task_id:
        return idx
    try:
        task = connector_get(f"/api/tasks/{task_id}")
    except Exception as e:
        print(f"[warn] connector task: {e}")
        return idx
    for r in task.get("records") or []:
        url = (r.get("url") or "").strip()
        key = note_key(url)
        idx[key] = {
            "title": (r.get("title") or "").strip(),
            "author": (r.get("author") or "").strip(),
            "url": url,
            "likes": int(r.get("likes") or 0),
            "content": (r.get("content") or "").strip(),
            "publish_time": (r.get("publishTime") or "").strip(),
        }
    return idx


def read_csv_file(csv_path: Path) -> tuple[list[str], list[dict]]:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        rows = [dict(r) for r in reader]
    for col in ENRICH_COLUMNS:
        if col not in fieldnames:
            fieldnames.append(col)
    return fieldnames, rows


def write_csv_file(csv_path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run_note_link(url: str) -> dict | None:
    if not GIT_BASH.is_file() or not WEB_COLLECTION.is_dir():
        return None
    safe_url = url.replace("'", "'\\''")
    cmd = [
        str(GIT_BASH), "-lc",
        (
            f"cd '{WEB_COLLECTION.as_posix()}' && "
            f"bash scripts/run.sh --connection-mode local --platform xiaohongshu "
            f"--method noteLink --link '{safe_url}' --max-items 1 --fetch-detail true "
            f"--detail-speed slow --auto-export false --ensure-bridge"
        ),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=120)
        text = proc.stdout + proc.stderr
        m = re.search(r'"taskId"\s*:\s*"(xiaohongshu-noteLink-[^"]+)"', text)
        if not m:
            return None
        task = connector_get(f"/api/tasks/{m.group(1)}")
        recs = task.get("records") or []
        return recs[0] if recs else None
    except Exception as e:
        print(f"[warn] noteLink: {e}")
        return None


TITLE_REPO_HINTS: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"5\.?4\s*万|54000|54k", re.I), ["virattt/ai-hedge-fund", "OpenBB-finance/OpenBB"]),
    (re.compile(r"7k|7000|七千", re.I), ["Future-House/aviary", "langchain-ai/deep-agents"]),
    (re.compile(r"stop-?slop|去ai味|去 AI 味", re.I), ["hardikpandya/stop-slop"]),
    (re.compile(r"superpowers", re.I), ["obra/superpowers"]),
    (re.compile(r"hallmark", re.I), ["Nutlope/hallmark"]),
    (re.compile(r"hyperframes|视频", re.I), ["heygen-com/hyperframes", "bradautomates/claude-video"]),
    (re.compile(r"design skill|设计", re.I), [
        "Leonxlnx/taste-skill", "Ilm-Alan/frontend-design", "alchaincyf/huashu-design",
    ]),
    (re.compile(r"anthropic|官方", re.I), ["anthropics/skills"]),
    (re.compile(r"vercel|skills\.sh", re.I), ["vercel-labs/agent-skills"]),
    (re.compile(r"小红书|redbook|rednote", re.I), [
        "comeonzhj/Auto-Redbook-Skills", "mythkiven/rednote-director-skill",
        "vivy-yi/xiaohongshu-skills",
    ]),
]


def hint_repos_from_title(title: str) -> list[str]:
    out: list[str] = []
    for pat, repos in TITLE_REPO_HINTS:
        if pat.search(title or ""):
            out.extend(repos)
    return out


def repos_for_text(title: str, content: str, url: str = "") -> list[str]:
    text = "\n".join([title or "", content or "", url or ""])
    found = xiaohongshu.extract_repos_from_text(text)
    found += hint_repos_from_title(title)
    seen: set[str] = set()
    out: list[str] = []
    for fn in found:
        k = fn.lower()
        if k not in seen:
            seen.add(k)
            out.append(fn)
    return out


def github_repo_api(full_name: str, token: str = "") -> dict | None:
    # 无 token 且 core 额度用尽时直接走 HTML，避免 403 重试浪费时间
    if not token:
        try:
            req = urllib.request.Request(
                "https://api.github.com/rate_limit",
                headers={"User-Agent": "skill-feed-xhs-loop/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                lim = json.loads(resp.read().decode("utf-8"))
            if int(((lim.get("rate") or {}).get("remaining") or 0)) <= 0:
                return github_repo_html_fallback(full_name)
        except Exception:
            pass
    url = f"https://api.github.com/repos/{full_name}"
    headers = {"User-Agent": "skill-feed-xhs-loop/1.0", "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (403, 429):
                return github_repo_html_fallback(full_name)
            raise
    return github_repo_html_fallback(full_name)


def github_repo_html_fallback(full_name: str) -> dict | None:
    url = f"https://github.com/{full_name}"
    req = urllib.request.Request(url, headers={"User-Agent": "skill-feed-xhs-loop/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    stars = 0
    m = re.search(r'id="repo-stars-counter-star"[^>]*>([^<]+)<', html)
    if not m:
        m = re.search(r'aria-label="(\d[\d,]*) users? starred', html)
    if m:
        raw = m.group(1).strip().replace(",", "")
        if raw.endswith("k"):
            stars = int(float(raw[:-1]) * 1000)
        else:
            try:
                stars = int(raw)
            except ValueError:
                stars = 0
    owner = full_name.split("/")[0]
    return {
        "full_name": full_name,
        "html_url": url,
        "description": "",
        "language": "",
        "stargazers_count": stars,
        "owner": {"login": owner},
        "pushed_at": "",
        "created_at": "",
    }


def validate_repo(
    full_name: str,
    meta: dict,
    *,
    min_stars: int,
    ua: str,
    gh_token: str,
    cache: dict[str, tuple[dict | None, str]],
) -> tuple[dict | None, str]:
    key = full_name.lower()
    if key in cache:
        return cache[key]
    api = github_repo_api(full_name, gh_token)
    if not api:
        cache[key] = (None, "github_404")
        return cache[key]
    stars = int(api.get("stargazers_count") or 0)
    owner = api.get("owner", {}).get("login") or full_name.split("/")[0]
    desc = api.get("description") or meta.get("note_title") or ""
    row = {
        "full_name": full_name,
        "url": api.get("html_url") or f"https://github.com/{full_name}",
        "description": desc,
        "language": api.get("language") or "",
        "stars": stars,
        "stars_today": 0,
        "source": "xiaohongshu",
        "owner": owner,
        "kind": "skill",
    }
    if stars < min_stars:
        cache[key] = (None, f"stars<{min_stars}({stars})")
        return cache[key]
    probed = skill_detect.enrich_repo(row, ua, always_probe=True)
    if not probed:
        cache[key] = (None, "no_skill_md")
        return cache[key]
    probed.update({
        "xhs_note_title": meta.get("note_title") or "",
        "xhs_note_url": meta.get("note_url") or "",
        "xhs_likes": meta.get("xhs_likes") or 0,
        "github_pushed_at": (api.get("pushed_at") or "")[:10],
    })
    scene.apply_scene(probed)
    cache[key] = (probed, "ok")
    return cache[key]


def to_bitable_row(item: dict) -> dict:
    fn = item["full_name"]
    ing = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")
    desc = (item.get("description") or "")[:500]
    return {
        "名称": (item.get("name") or fn.split("/")[-1])[:200],
        "仓库全名": fn,
        "来源": "小红书",
        "发布人": item.get("owner") or fn.split("/")[0],
        "发布时间": item.get("github_pushed_at") or item.get("xhs_note_title", "")[:80],
        "GitHub链接": item.get("url") or f"https://github.com/{fn}",
        "分类": classify(item),
        "二级分类": (item.get("scene_l2_label") or "")[:100],
        "关键词": keywords_for(item, fn),
        "评星": int(item.get("stars") or 0),
        "描述": desc,
        "HelloGitHub期数": None,
        "收录时间": ing,
        "数据池": "主Feed",
    }


def enrich_row_content(
    row: dict,
    conn_idx: dict[str, dict],
    *,
    note_link_limit: int,
    note_link_used: list[int],
) -> str:
    url = (row.get("笔记链接") or row.get("url") or "").strip()
    key = note_key(url)
    content = (row.get("正文") or row.get("content") or "").strip()
    if not content and key in conn_idx:
        content = conn_idx[key].get("content") or ""
    if not content and note_link_used[0] < note_link_limit and url:
        rec = run_note_link(url)
        note_link_used[0] += 1
        if rec and (rec.get("content") or "").strip():
            content = rec["content"].strip()
            print(f"  noteLink[{note_link_used[0]}] OK {(row.get('标题') or '')[:36]}")
        else:
            print(f"  noteLink[{note_link_used[0]}] skip {(row.get('标题') or '')[:36]}")
        time.sleep(1.2)
    return content


def update_csv_inplace(
    csv_path: Path,
    *,
    conn_idx: dict[str, dict],
    min_stars: int,
    ua: str,
    gh_token: str,
    note_link_limit: int,
    note_link_used: list[int],
    validation_cache: dict[str, tuple[dict | None, str]],
    passed_global: dict[str, dict],
) -> tuple[int, int]:
    """原地更新 CSV，返回 (enriched_rows, passed_repos_this_file)。"""
    fieldnames, rows = read_csv_file(csv_path)
    enriched = 0
    ts = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")
    passed_here = 0

    for row in rows:
        title = (row.get("标题") or row.get("title") or "").strip()
        url = (row.get("笔记链接") or row.get("url") or "").strip()
        content = enrich_row_content(
            row, conn_idx, note_link_limit=note_link_limit, note_link_used=note_link_used,
        )
        if content and content != (row.get("正文") or "").strip():
            row["正文"] = content[:2000]
            enriched += 1

        repos = repos_for_text(title, content, url)
        statuses: list[str] = []
        stars_list: list[str] = []
        pass_count = 0
        for fn in repos:
            meta = {
                "full_name": fn,
                "note_title": title,
                "note_url": url,
                "xhs_likes": int(str(row.get("点赞数") or 0).replace(",", "") or 0),
            }
            item, reason = validate_repo(
                fn, meta, min_stars=min_stars, ua=ua, gh_token=gh_token, cache=validation_cache,
            )
            if reason.startswith("stars<"):
                m = re.search(r"\((\d+)\)", reason)
                stars_list.append(m.group(1) if m else "?")
            elif item:
                stars_list.append(str(item.get("stars") or 0))
            else:
                stars_list.append("-")
            statuses.append(f"{fn}:{reason}")
            if item:
                pass_count += 1
                passed_global[fn.lower()] = item
                passed_here += 1

        row["提取GitHub仓"] = "; ".join(repos) if repos else ""
        row["校验状态"] = "; ".join(statuses) if statuses else "无链接"
        row["评星"] = "; ".join(stars_list) if stars_list else ""
        if not repos:
            row["是否通过门禁"] = "无仓"
        elif pass_count == len(repos):
            row["是否通过门禁"] = "是"
        elif pass_count > 0:
            row["是否通过门禁"] = "部分"
        else:
            row["是否通过门禁"] = "否"
        row["更新时间"] = ts

    write_csv_file(csv_path, fieldnames, rows)
    print(f"[csv] 原地更新 {csv_path.name}: {len(rows)} 行, 正文补全 {enriched} 行")
    return len(rows), passed_here


def resolve_target(base_token: str, table_id: str) -> tuple[str, str]:
    if base_token and table_id:
        return base_token, table_id
    if TARGET_JSON.is_file():
        t = json.loads(TARGET_JSON.read_text(encoding="utf-8"))
        return t["base_token"], t["table_id"]
    raise SystemExit("请提供 --base-token/--table-id 或先 create-and-push 生成 target.json")


def push_rows(rows: list[dict], base_token: str, table_id: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for i in range(0, len(rows), 200):
        batch = rows[i : i + 200]
        p = OUT_DIR / f"xhs_batch_{i // 200 + 1:03d}.json"
        p.write_text(json.dumps({"create_records": batch}, ensure_ascii=False), encoding="utf-8")
        print(f"[bitable] push {p.name} ({len(batch)} rows)")
        run_lark(
            [
                "base", "+record-batch-create",
                "--as", "user",
                "--base-token", base_token,
                "--table-id", table_id,
                "--json", f"@{p.name}",
            ],
            cwd=OUT_DIR,
        )


def cmd_run(csv_paths: list[Path], base_token: str, table_id: str, note_link_limit: int) -> int:
    cfg = load_cfg()
    min_stars = int(cfg.get("min_stars", MIN_STARS_DEFAULT))
    ua = cfg.get("user_agent", "skill-feed/0.3")
    gh_token = os.environ.get("GITHUB_TOKEN") or cfg.get("github_token") or ""

    if not ensure_connector():
        print("[warn] connector 未连接，跳过 noteLink，仅用标题/connector 缓存")

    conn_idx = load_connector_index()
    print(f"[xhs] connector 缓存 {len(conn_idx)} 条笔记")

    validation_cache: dict[str, tuple[dict | None, str]] = {}
    passed_global: dict[str, dict] = {}
    total_rows = 0
    note_link_used = [0]

    for csv_path in csv_paths:
        if not csv_path.is_file():
            print(f"[skip] 不存在: {csv_path}")
            continue
        n, _ = update_csv_inplace(
            csv_path,
            conn_idx=conn_idx,
            min_stars=min_stars,
            ua=ua,
            gh_token=gh_token,
            note_link_limit=note_link_limit,
            note_link_used=note_link_used,
            validation_cache=validation_cache,
            passed_global=passed_global,
        )
        # 把本文件已写回的正文并入索引，供同内容的第二份 CSV 复用
        _, rows_now = read_csv_file(csv_path)
        for r in rows_now:
            u = (r.get("笔记链接") or "").strip()
            c = (r.get("正文") or "").strip()
            if u and c:
                conn_idx[note_key(u)] = {
                    **conn_idx.get(note_key(u), {}),
                    "url": u,
                    "content": c,
                    "title": (r.get("标题") or "").strip(),
                }
        total_rows += n

    passed = list(passed_global.values())
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "csv_files": [str(p) for p in csv_paths],
        "rows_updated": total_rows,
        "candidates_validated": len(validation_cache),
        "passed": len(passed),
        "rejected": [
            {"full_name": k, "reason": v[1]}
            for k, v in validation_cache.items() if v[1] != "ok"
        ],
        "min_stars": min_stars,
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"[xhs] 校验完成: 候选 {len(validation_cache)} | 通过 {len(passed)} | min_stars={min_stars}")

    if not passed:
        print("[xhs] 无通过门禁的 skill，未写入 bitable")
        return 1

    bt, tid = resolve_target(base_token, table_id)
    rows = [to_bitable_row(x) for x in passed]
    push_rows(rows, bt, tid)
    print(f"[done] {len(passed)} 条写入 bitable https://trip.larkenterprise.com/base/{bt}")
    return 0


def cmd_audit_stars(base_token: str, table_id: str) -> int:
    cfg = load_cfg()
    min_stars = int(cfg.get("min_stars", MIN_STARS_DEFAULT))
    bt, tid = resolve_target(base_token, table_id)
    print(f"[audit] min_stars={min_stars} base={bt} table={tid}")
    proc = subprocess.run(
        [lark_bin(), "base", "+record-list", "--as", "user",
         "--base-token", bt, "--table-id", tid, "--format", "ndjson"],
        capture_output=True, text=True, encoding="utf-8",
        shell=(os.name == "nt" and lark_bin().lower().endswith(".cmd")),
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout)
    total = 0
    bad_stars = 0
    no_stars = 0
    xhs = 0
    by_source: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        total += 1
        fields = rec.get("fields") or rec
        src = fields.get("来源") or fields.get("source") or "?"
        by_source[src] = by_source.get(src, 0) + 1
        if src == "小红书":
            xhs += 1
        stars = fields.get("评星")
        if stars is None or stars == "":
            no_stars += 1
        elif float(stars) < min_stars:
            bad_stars += 1
            print(f"  LOW {stars}★ {fields.get('仓库全名') or fields.get('名称')} [{src}]")
    print(f"[audit] 总记录 {total} | 来源 {by_source}")
    print(f"[audit] 小红书 {xhs} | 无评星 {no_stars} | 低于门槛 {bad_stars}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_run = sub.add_parser("run")
    p_run.add_argument("--csv", type=Path, action="append", default=[])
    p_run.add_argument("--base-token", default="")
    p_run.add_argument("--table-id", default="")
    p_run.add_argument("--note-link-limit", type=int, default=8)
    p_audit = sub.add_parser("audit-stars")
    p_audit.add_argument("--base-token", default="")
    p_audit.add_argument("--table-id", default="")
    args = ap.parse_args()

    csvs = args.csv or [
        DEFAULT_CSV_DIR / "github skills 小红书更新0902.csv",
        DEFAULT_CSV_DIR / "github skills 小红书更新0902-1.csv",
    ]
    if args.cmd == "run":
        return cmd_run(csvs, args.base_token, args.table_id, args.note_link_limit)
    if args.cmd == "audit-stars":
        return cmd_audit_stars(args.base_token, args.table_id)
    return 1


if __name__ == "__main__":
    sys.exit(main())
