#!/usr/bin/env python3
"""从「通往AGI之路」知识库更新批次：能落到 GitHub 的一律进飞书底表。

分层（PRD §6.0）：
- 飞书底表：全、准确；不论是不是 skill
- skill-feed：再按 gates 筛进信息流（本脚本 --merge-feed 只是灌 corpus，不替代 refresh 门禁）

- 写入 ~/.skill-feed/corpus/waytoagi/
- 可选 --merge-feed / --push-bitable
- 飞书「来源」写「策展目录」，关键词保留 WaytoAGI 出处
- 退出码：0=至少 1 条成功；1=全部失败（必须通知用户）

用法（skill-feed 仓库根）:
  python scripts/ingest_waytoagi.py [--merge-feed] [--push-bitable] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import corpus as corpus_mod  # noqa: E402
import scene  # noqa: E402
from export_to_bitable import run_lark  # noqa: E402

HOME = Path.home()
DATA = HOME / ".skill-feed"
FEED = DATA / "feed.json"
TARGET = DATA / "bitable_export" / "target.json"
OUT = DATA / "bitable_export" / "waytoagi"
NOTE = ROOT / "docs" / "waytoagi-kb-batch.md"

# 本批从飞书 Wiki 正文抽出、且 gh api 可解析的仓（见 docs/waytoagi-kb-batch.md）
CURATED: list[dict] = [
    {
        "full_name": "Pluviobyte/rnskill",
        "kind": "skill",
        "topic": "雪踏乌云 55 个 AI 视频 Skill 全集",
        "wiki": "D9VMwrysnibtO8kyzsHcPhqvnLe",
        "cat": "内容",
    },
    {
        "full_name": "dontbesilent2025/dbskill",
        "kind": "skill",
        "topic": "dontbesilent 商业诊断 Skills（与 rnskill 同文引用）",
        "wiki": "D9VMwrysnibtO8kyzsHcPhqvnLe",
        "cat": "业务",
    },
    {
        "full_name": "xiaohuailabs/xiaohu-video-translate",
        "kind": "skill",
        "topic": "外语视频本地转写翻译烧录一条龙",
        "wiki": "D9VMwrysnibtO8kyzsHcPhqvnLe",
        "cat": "内容",
    },
    {
        "full_name": "freestylefly/codex-themes",
        "kind": "toolkit",
        "topic": "苍何：Codex Themes 换肤工具（开源）",
        "wiki": "HOcvwNEVEi8PdlkDAORci0Ipnzc",
        "cat": "开发",
    },
    {
        "full_name": "freestylefly/canghe-skills",
        "kind": "skill",
        "topic": "苍何 Claude Code skills 合集",
        "wiki": "HOcvwNEVEi8PdlkDAORci0Ipnzc",
        "cat": "开发",
    },
    {
        "full_name": "yunshu0909/yunshu_skillshub",
        "kind": "skill",
        "topic": "云舒：最常用的 Skills 精选 hub",
        "wiki": "LvIvw3L7uiUJTxk0W0ecYrIsnDg",
        "cat": "开发",
    },
    {
        "full_name": "Agentchengfeng/chengfeng-landingpage",
        "kind": "skill",
        "topic": "成峰：开源首页设计 Skill（视频驱动 landing）",
        "wiki": "Xtj6w2xu7ig3YokjWUMcttaJngb",
        "cat": "设计",
    },
    {
        "full_name": "simonlin000/x-scan",
        "kind": "toolkit",
        "topic": "Simonlin：X/Twitter AI 资讯扫描器",
        "wiki": "Pk7YwOi3qiyI7Okk61RcBHHGnuh",
        "cat": "内容",
    },
    {
        "full_name": "buluslan/amazon-listing-doctor",
        "kind": "skill",
        "topic": "Blue：亚马逊 Listing 质检打分 Skill",
        "wiki": "Yj9NwpFkVihly4kEIVocjzoCnTb",
        "cat": "业务",
    },
    {
        "full_name": "antvis/Infographic",
        "kind": "toolkit",
        "topic": "AntV Infographic：几句话生成 SVG 信息图",
        "wiki": "NYOcwsVs7iPXUQkYzQzcCDVmnGf",
        "cat": "设计",
    },
    {
        "full_name": "yc-software/qm",
        "kind": "agent",
        "topic": "YC 开源多 Agent 协作框架 QM",
        "wiki": "UFOOwTTJmixn2akLI7ncbwTDnNe",
        "cat": "开发",
    },
    {
        "full_name": "anomalyco/opencode",
        "kind": "agent",
        "topic": "OpenCode：开源 coding agent（ARR/增长案例文）",
        "wiki": "PSZOw8b94iAbO1kphYOc772Inac",
        "cat": "开发",
    },
    {
        "full_name": "D4Vinci/Scrapling",
        "kind": "toolkit",
        "topic": "Scrapling：Agent 批量采集网页",
        "wiki": "LW6pwiRHSiU9IckyqH2clM1FnBb",
        "cat": "数据",
    },
    {
        "full_name": "awplanets/awplanet",
        "kind": "toolkit",
        "topic": "AI 原生 3D 导演工作台",
        "wiki": "CjSRwtPg6iZ2hWkfTOpcc2KqnUh",
        "cat": "内容",
    },
    {
        "full_name": "liucongg/awesome-open-llms",
        "kind": "oss",
        "topic": "刘聪NLP：awesome-open-llms 开源模型大盘",
        "wiki": "E7KewSqVeimQQ8kGDALcVkvhnWg",
        "cat": "研究",
    },
    {
        "full_name": "ibelick/ui-skills",
        "kind": "skill",
        "topic": "本周 TOP GitHub：Design Engineer UI Skills",
        "wiki": "TfFswikBRiWoKzkqm2Mcs3E7ndd",
        "cat": "设计",
    },
    {
        "full_name": "MoonshotAI/kimi-cli",
        "kind": "agent",
        "topic": "本周 TOP：Kimi Code CLI",
        "wiki": "TfFswikBRiWoKzkqm2Mcs3E7ndd",
        "cat": "开发",
    },
    {
        "full_name": "MoonshotAI/kimi-code",
        "kind": "agent",
        "topic": "本周 TOP：Kimi Code 起点仓",
        "wiki": "TfFswikBRiWoKzkqm2Mcs3E7ndd",
        "cat": "开发",
    },
    {
        "full_name": "bojieli/ai-agent-book",
        "kind": "oss",
        "topic": "本周 TOP：深入理解 AI Agent 开源书",
        "wiki": "TfFswikBRiWoKzkqm2Mcs3E7ndd",
        "cat": "研究",
    },
    {
        "full_name": "1jehuang/jcode",
        "kind": "toolkit",
        "topic": "本周 TOP：jcode RAM 高效 harness",
        "wiki": "TfFswikBRiWoKzkqm2Mcs3E7ndd",
        "cat": "开发",
    },
    {
        "full_name": "agegr/pi-web",
        "kind": "toolkit",
        "topic": "本周 TOP：pi coding agent Web UI",
        "wiki": "TfFswikBRiWoKzkqm2Mcs3E7ndd",
        "cat": "开发",
    },
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def gh_api_repo(full_name: str) -> dict | None:
    try:
        from gh_validate import validate_github_full_name
        full_name = validate_github_full_name(full_name)
    except Exception:  # noqa: BLE001
        return None
    p = subprocess.run(
        ["gh", "api", f"repos/{full_name}"],
        capture_output=True,
        timeout=30,
    )
    if p.returncode != 0:
        return None
    return json.loads(p.stdout.decode("utf-8", errors="replace"))


def has_path(full_name: str, path: str) -> bool:
    try:
        from gh_validate import validate_github_full_name
        full_name = validate_github_full_name(full_name)
    except Exception:  # noqa: BLE001
        return False
    p = subprocess.run(
        ["gh", "api", f"repos/{full_name}/contents/{path}"],
        capture_output=True,
        timeout=30,
    )
    return p.returncode == 0


def detect_skill_path(full_name: str) -> str:
    for path in ("SKILL.md", "skills", ".claude/skills", "agents"):
        if has_path(full_name, path):
            return path
    return ""


def to_item(meta: dict, curated: dict) -> dict:
    fn = curated["full_name"]
    owner, name = fn.split("/", 1)
    skill_path = detect_skill_path(fn)
    kind = curated["kind"]
    if skill_path and kind in ("oss", "research", "toolkit"):
        kind = "skill"
    wiki = curated.get("wiki") or ""
    row = {
        "id": f"wagi:{fn}",
        "full_name": fn,
        "name": name,
        "owner": owner,
        "description": (meta.get("description") or curated.get("topic") or "")[:500],
        "url": meta.get("html_url") or f"https://github.com/{fn}",
        "source": "catalog",
        "kind": kind,
        "mode": "skills" if kind == "skill" else ("ai" if kind in ("mcp", "agent", "protocol") else "oss"),
        "hg_section": "WaytoAGI",
        "skill_path": skill_path,
        "stars": int(meta.get("stargazers_count") or 0),
        "stars_today": 0,
        "github_pushed_at": (meta.get("pushed_at") or "")[:16],
        "topic": curated.get("topic") or "",
        "wiki_token": wiki,
        "wiki_url": f"https://waytoagi.feishu.cn/wiki/{wiki}" if wiki else "",
        "body_preview": (
            f"WaytoAGI KB: {curated.get('topic')}. "
            f"Wiki: {wiki}."
        ),
        "ingested_at": _now(),
        "from_corpus": True,
        "bitable_cat": curated.get("cat") or "开发",
    }
    return scene.apply_scene(row)


def ingest_corpus(items: list[dict]) -> dict:
    root = corpus_mod.corpus_root(DATA)
    wa_dir = root / "waytoagi"
    gh_dir = root / "github" / "repos"
    index_path = root / corpus_mod.INDEX_NAME
    root.mkdir(parents=True, exist_ok=True)
    wa_dir.mkdir(parents=True, exist_ok=True)
    existing = corpus_mod._load_index_keys(index_path)
    added = 0
    updated = 0
    new_rows: list[dict] = []
    for it in items:
        fn = it["full_name"]
        cid = it["id"]
        owner, repo = fn.split("/", 1)
        dest = gh_dir / owner / repo
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "meta.json").write_text(
            json.dumps(it, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (wa_dir / f"{owner}__{repo}.json").write_text(
            json.dumps(it, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        if cid in existing or f"gh:{fn}" in existing or f"td:{fn}" in existing:
            updated += 1
            continue
        new_rows.append(it)
        existing.add(cid)
        added += 1
    corpus_mod._append_index(index_path, new_rows)
    snap = {
        "updated_at": _now(),
        "source": "waytoagi",
        "added": added,
        "updated_files": updated,
        "count": len(items),
        "items": [x["full_name"] for x in items],
    }
    (wa_dir / "meta.json").write_text(
        json.dumps(snap, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return snap


def merge_feed(items: list[dict]) -> int:
    if not FEED.is_file():
        print("[merge-feed] no feed.json, skip")
        return 0
    data = json.loads(FEED.read_text(encoding="utf-8"))
    corpus = list(data.get("corpus") or [])
    by = {(x.get("full_name") or "").lower(): i for i, x in enumerate(corpus)}
    n = 0
    for it in items:
        key = it["full_name"].lower()
        card = dict(it)
        card["from_corpus"] = True
        card["source"] = "catalog"
        if key in by:
            prev = corpus[by[key]]
            merged = dict(prev)
            merged.update({k: v for k, v in card.items() if v not in (None, "", [])})
            corpus[by[key]] = merged
        else:
            corpus.insert(0, card)
            n += 1
    data["corpus"] = corpus
    data["waytoagi_ingested_at"] = _now()
    FEED.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return n


def to_bitable_row(it: dict) -> dict:
    fn = it["full_name"]
    kind = it.get("kind") or ""
    cat = it.get("bitable_cat") or {
        "mcp": "开发",
        "skill": "开发",
        "agent": "开发",
        "protocol": "开发",
        "toolkit": "开发",
        "research": "研究",
        "oss": "其他",
    }.get(kind, "开发")
    wiki = it.get("wiki_url") or ""
    kws = ["WaytoAGI", kind, it.get("topic") or "", wiki]
    kws = [k for k in kws if k]
    return {
        "名称": (it.get("name") or fn.split("/")[-1])[:200],
        "仓库全名": fn,
        "来源": "策展目录",
        "发布人": it.get("owner") or fn.split("/")[0],
        "发布时间": (it.get("github_pushed_at") or "")[:16],
        "GitHub链接": it.get("url") or f"https://github.com/{fn}",
        "分类": cat,
        "二级分类": f"WaytoAGI · {kind}",
        "关键词": " · ".join(kws)[:200],
        "评星": int(it.get("stars") or 0),
        "描述": (it.get("description") or it.get("topic") or "")[:500],
        "收录时间": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"),
        "数据池": "知识库",
    }


def push_bitable(items: list[dict]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = [to_bitable_row(x) for x in items]
    batch = OUT / "batch_001.json"
    batch.write_text(json.dumps({"create_records": rows}, ensure_ascii=False), encoding="utf-8")
    (OUT / "preview.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    target = json.loads(TARGET.read_text(encoding="utf-8"))
    bt, tid = target["base_token"], target["table_id"]
    print(f"[bitable] push {len(rows)} → {bt} / {tid}")
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
            "@batch_001.json",
        ],
        cwd=OUT,
    )
    print(f"[bitable] done → https://trip.larkenterprise.com/base/{bt}")


def write_status(status: str, detail: str, count: int, failed: list[str]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": status,
        "checked_at": _now(),
        "count": count,
        "failed": failed,
        "detail": detail,
        "must_notify": status != "UPDATED",
    }
    (OUT / "latest-ingest-status.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if status != "UPDATED":
        alert = OUT / "INGEST_ALERT.md"
        alert.write_text(
            f"# WaytoAGI ingest alert\n\n- status: **{status}**\n- detail: {detail}\n"
            f"- failed: {', '.join(failed) or '-'}\n\n"
            "Agent MUST notify the user in Simplified Chinese.\n",
            encoding="utf-8",
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--push-bitable", action="store_true")
    ap.add_argument("--merge-feed", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    items: list[dict] = []
    failed: list[str] = []
    for c in CURATED:
        meta = gh_api_repo(c["full_name"])
        if not meta:
            print(f"[miss] {c['full_name']}")
            failed.append(c["full_name"])
            continue
        it = to_item(meta, c)
        items.append(it)
        print(
            f"[ok] {it['stars']:6d} | {it['kind']:8s} | "
            f"{it['full_name']} | skill_path={it.get('skill_path') or '-'}"
        )

    if args.dry_run:
        print(f"[dry-run] resolved={len(items)} failed={len(failed)}")
        return 0 if items else 1

    if not items:
        write_status("FETCH_FAILED", "all curated repos missed", 0, failed)
        print("[FAIL] no items — must notify user")
        return 1

    snap = ingest_corpus(items)
    print(f"[corpus] added={snap['added']} touched={snap['updated_files']} total={snap['count']}")

    if args.merge_feed:
        n = merge_feed(items)
        print(f"[feed] corpus inserted/updated, new={n}")

    if args.push_bitable:
        try:
            push_bitable(items)
        except Exception as e:  # noqa: BLE001 — 飞书推表失败必须落到通知，不能漏网
            write_status("PUSH_FAILED", str(e), len(items), failed)
            print(f"[FAIL] bitable push: {e} — must notify user")
            return 1

    write_status(
        "UPDATED",
        f"ingested {len(items)}; failed {len(failed)}",
        len(items),
        failed,
    )
    print(f"[note] see {NOTE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
