#!/usr/bin/env python3
"""从 GitHub《The Download》近窗提到的 MCP / Skills / Agent 工具链入库。

- 写入 ~/.skill-feed/corpus/（知识库，只增不删）
- 可选合并进 feed.json 的 corpus 池（供 build / Pages）
- 导出并推飞书多维表格（来源=The Download）

用法（在 skill-feed 仓库根）:
  python scripts/ingest_the_download.py [--push-bitable] [--merge-feed] [--dry-run]
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
OUT = DATA / "bitable_export" / "the_download"
NOTE = ROOT / "docs" / "the-download-mcp-skills.md"

# 节目里明确点名、且可落到 GitHub 的 MCP / Skills / Agent 工具链
# episode 索引见 docs/the-download-mcp-skills.md
CURATED: list[dict] = [
    {
        "full_name": "github/github-mcp-server",
        "kind": "mcp",
        "topic": "GitHub 官方 MCP Server / Registry / Remote MCP",
        "episodes": ["024", "031", "036"],
    },
    {
        "full_name": "modelcontextprotocol/servers",
        "kind": "mcp",
        "topic": "MCP 官方 reference servers",
        "episodes": ["013", "024", "036"],
    },
    {
        "full_name": "modelcontextprotocol/python-sdk",
        "kind": "mcp",
        "topic": "MCP Python SDK",
        "episodes": ["036"],
    },
    {
        "full_name": "modelcontextprotocol/typescript-sdk",
        "kind": "mcp",
        "topic": "MCP TypeScript SDK",
        "episodes": ["036"],
    },
    {
        "full_name": "PrefectHQ/fastmcp",
        "kind": "mcp",
        "topic": "FastMCP（节目「MCP funeral」梗相关）",
        "episodes": ["013"],
    },
    {
        "full_name": "docker/mcp-gateway",
        "kind": "mcp",
        "topic": "Docker MCP Gateway / Toolkit",
        "episodes": ["034"],
    },
    {
        "full_name": "microsoft/azure-devops-mcp",
        "kind": "mcp",
        "topic": "Azure DevOps MCP Server",
        "episodes": ["031"],
    },
    {
        "full_name": "a2aproject/A2A",
        "kind": "protocol",
        "topic": "Agent2Agent (A2A) 协议（进 Agentic AI Foundation）",
        "episodes": ["002"],
    },
    {
        "full_name": "a2aproject/a2a-python",
        "kind": "protocol",
        "topic": "A2A Python SDK",
        "episodes": ["002"],
    },
    {
        "full_name": "github/awesome-copilot",
        "kind": "skill",
        "topic": "Copilot 社区 instructions / agents / skills",
        "episodes": ["014", "024"],
    },
    {
        "full_name": "github/spec-kit",
        "kind": "toolkit",
        "topic": "spec-kit 规范驱动开发工具包",
        "episodes": ["023"],
    },
    {
        "full_name": "openclaw/openclaw",
        "kind": "agent",
        "topic": "OpenClaw 本机 AI agent 平台",
        "episodes": ["015", "016"],
    },
    {
        "full_name": "VoltAgent/awesome-openclaw-skills",
        "kind": "skill",
        "topic": "OpenClaw skills 集合",
        "episodes": ["015", "016"],
    },
    {
        "full_name": "openai/openai-agents-python",
        "kind": "agent",
        "topic": "OpenAI Agents SDK（AgentKit 生态）",
        "episodes": ["023"],
    },
    {
        "full_name": "openai/openai-agents-js",
        "kind": "agent",
        "topic": "OpenAI Agents JS SDK",
        "episodes": ["023"],
    },
    {
        "full_name": "TanStack/ai",
        "kind": "toolkit",
        "topic": "TanStack AI 框架无关 toolkit",
        "episodes": ["010"],
    },
    {
        "full_name": "omacom/ttfx",
        "kind": "oss",
        "topic": "ttfx 终端动画（Project pick）",
        "episodes": ["002"],
    },
    {
        "full_name": "louisabraham/load-bearing",
        "kind": "research",
        "topic": "Claude PR「承重词汇」分析",
        "episodes": ["001"],
    },
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def gh_api_repo(full_name: str) -> dict | None:
    p = subprocess.run(
        ["gh", "api", f"repos/{full_name}"],
        capture_output=True,
    )
    if p.returncode != 0:
        return None
    return json.loads(p.stdout.decode("utf-8", errors="replace"))


def has_path(full_name: str, path: str) -> bool:
    p = subprocess.run(
        ["gh", "api", f"repos/{full_name}/contents/{path}"],
        capture_output=True,
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
    row = {
        "id": f"td:{fn}",
        "full_name": fn,
        "name": name,
        "owner": owner,
        "description": (meta.get("description") or curated.get("topic") or "")[:500],
        "url": meta.get("html_url") or f"https://github.com/{fn}",
        "source": "the-download",
        "kind": kind,
        "mode": "skills" if kind == "skill" else ("ai" if kind in ("mcp", "agent", "protocol") else "oss"),
        "hg_section": "The Download",
        "skill_path": skill_path,
        "stars": int(meta.get("stargazers_count") or 0),
        "stars_today": 0,
        "github_pushed_at": (meta.get("pushed_at") or "")[:16],
        "topic": curated.get("topic") or "",
        "episodes": curated.get("episodes") or [],
        "body_preview": (
            f"The Download mentions: {curated.get('topic')}. "
            f"Episodes: {', '.join(curated.get('episodes') or [])}."
        ),
        "ingested_at": _now(),
        "from_corpus": True,
    }
    return scene.apply_scene(row)


def ingest_corpus(items: list[dict]) -> dict:
    root = corpus_mod.corpus_root(DATA)
    td_dir = root / "the-download"
    gh_dir = root / "github" / "repos"
    index_path = root / corpus_mod.INDEX_NAME
    root.mkdir(parents=True, exist_ok=True)
    td_dir.mkdir(parents=True, exist_ok=True)
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
        (td_dir / f"{owner}__{repo}.json").write_text(
            json.dumps(it, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        if cid in existing or f"gh:{fn}" in existing:
            updated += 1
            continue
        new_rows.append(it)
        existing.add(cid)
        added += 1
    corpus_mod._append_index(index_path, new_rows)
    snap = {
        "updated_at": _now(),
        "source": "the-download",
        "added": added,
        "updated_files": updated,
        "count": len(items),
        "items": [x["full_name"] for x in items],
    }
    (td_dir / "meta.json").write_text(json.dumps(snap, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
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
        if key in by:
            prev = corpus[by[key]]
            merged = dict(prev)
            merged.update({k: v for k, v in card.items() if v not in (None, "", [])})
            # keep richer source label but mark the-download
            merged["source"] = "the-download"
            corpus[by[key]] = merged
        else:
            corpus.insert(0, card)
            n += 1
    data["corpus"] = corpus
    data["the_download_ingested_at"] = _now()
    FEED.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return n


def to_bitable_row(it: dict) -> dict:
    fn = it["full_name"]
    kind = it.get("kind") or ""
    cat = {
        "mcp": "开发",
        "skill": "开发",
        "agent": "开发",
        "protocol": "开发",
        "toolkit": "开发",
        "research": "研究",
        "oss": "其他",
    }.get(kind, "开发")
    kws = ["The Download", kind, "MCP" if kind == "mcp" else "", it.get("topic") or ""]
    kws = [k for k in kws if k]
    return {
        "名称": (it.get("name") or fn.split("/")[-1])[:200],
        "仓库全名": fn,
        "来源": "The Download",
        "发布人": it.get("owner") or fn.split("/")[0],
        "发布时间": (it.get("github_pushed_at") or "")[:16],
        "GitHub链接": it.get("url") or f"https://github.com/{fn}",
        "分类": cat,
        "二级分类": f"The Download · {kind}",
        "关键词": " · ".join(kws)[:200],
        "评星": int(it.get("stars") or 0),
        "描述": (it.get("description") or it.get("topic") or "")[:500],
        "收录时间": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"),
        "数据池": "知识库",
    }


def push_bitable(items: list[dict]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    # 飞书「来源」枚举暂无 The Download，统一写策展目录，关键词保留出处
    rows = [to_bitable_row(x) for x in items]
    for r in rows:
        r["来源"] = "策展目录"
        kw = r.get("关键词") or ""
        if "The Download" not in kw:
            r["关键词"] = ("The Download · " + kw)[:200]
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

    snap = ingest_corpus(items)
    print(f"[corpus] added={snap['added']} touched={snap['updated_files']} total={snap['count']}")

    if args.merge_feed:
        n = merge_feed(items)
        print(f"[feed] corpus inserted/updated, new={n}")

    if args.push_bitable:
        push_bitable(items)

    print(f"[note] see {NOTE}")
    return 0 if items else 1


if __name__ == "__main__":
    raise SystemExit(main())
