#!/usr/bin/env python3
"""Gate-check WaytoAGI 底表 batches for skill-feed (does not merge feed)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gates  # noqa: E402
from gates import description_shape_reason  # noqa: E402

HOME = Path.home()
DATA = HOME / ".skill-feed"
OUT = DATA / "bitable_export" / "waytoagi_wiki"
SKILL_DIRS = {"skills", "agents"}
SKILL_FILES = {"skill.md"}
NESTED = {".claude", ".cursor", ".agents"}
_MCP_NAME_RE = re.compile(
    r"(?:^|/)(?:mcp(?:[-_]|$)|[-_]mcp$)|(?:^|/)[-\w]*mcp[-\w]*(?:/|$)",
    re.I,
)


def is_mcp_repo(full_name: str, name: str = "", description: str = "") -> bool:
    """仓名或描述明确是 MCP，不把「文里提到一句 MCP」的 skill 合集算进来。"""
    fn = (full_name or "").strip()
    repo = fn.split("/")[-1] if fn else ""
    blob_name = f"{repo} {name or ''}".lower()
    desc = (description or "").lower()
    if "mcp" in repo.lower() or repo.lower() in {"servers"} and "modelcontextprotocol" in fn.lower():
        return True
    if _MCP_NAME_RE.search(fn):
        return True
    if "model context protocol" in desc:
        return True
    if "mcp server" in desc or "mcp 服务" in desc or "mcp 服务器" in desc:
        return True
    if "mcp server" in blob_name or blob_name.strip().endswith("mcp"):
        return True
    return False


def _rows_from(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "create_records" in data:
        return list(data.get("create_records") or [])
    if isinstance(data, list):
        return data
    return []


def load_bottom() -> dict[str, dict]:
    rows: dict[str, dict] = {}
    paths = []
    wagi = DATA / "bitable_export" / "waytoagi"
    if wagi.is_dir():
        paths.extend(sorted(wagi.glob("*batch*.json")))
        paths.append(wagi / "preview.json")
    paths.extend(sorted(OUT.glob("batch_*.json")))
    for p in paths:
        wave = p.stem
        for r in _rows_from(p):
            fn = (r.get("仓库全名") or "").strip()
            if not fn:
                continue
            key = fn.lower()
            rec = dict(r)
            rec["_wave"] = wave
            wave_num = wave.split("_")[-1] if wave.startswith("batch_") else ""
            rec["_from_new_wave"] = wave_num.isdigit() and int(wave_num) >= 4
            if key not in rows or rec["_from_new_wave"]:
                rows[key] = rec
    return rows


def load_cached_paths() -> dict[str, str]:
    p = OUT / "feed_candidates.json"
    if not p.is_file():
        return {}
    try:
        rows = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    out: dict[str, str] = {}
    for r in rows:
        fn = (r.get("full_name") or "").lower()
        sp = r.get("skill_path") or ""
        if fn and sp:
            out[fn] = sp
    return out


def probe_root(full_name: str) -> str:
    try:
        from gh_validate import validate_github_full_name
        full_name = validate_github_full_name(full_name)
    except Exception:  # noqa: BLE001
        return ""
    try:
        p = subprocess.run(
            ["gh", "api", f"repos/{full_name}/contents"],
            capture_output=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""
    if p.returncode != 0:
        return ""
    try:
        items = json.loads(p.stdout.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return ""
    if not isinstance(items, list):
        return ""
    names = {str(x.get("name") or "") for x in items}
    lower = {n.lower(): n for n in names}
    if "skill.md" in lower:
        return lower["skill.md"]
    for d in SKILL_DIRS:
        if d in lower:
            return lower[d]
    for nest in NESTED:
        if nest in names:
            try:
                q = subprocess.run(
                    ["gh", "api", f"repos/{full_name}/contents/{nest}"],
                    capture_output=True,
                    timeout=30,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
            if q.returncode != 0:
                continue
            try:
                kids = json.loads(q.stdout.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(kids, list) and any(
                (k.get("name") or "").lower() == "skills" for k in kids
            ):
                return f"{nest}/skills"
    return ""


def feed_sets() -> tuple[set[str], set[str]]:
    items: set[str] = set()
    corpus: set[str] = set()
    feed_p = DATA / "feed.json"
    if feed_p.is_file():
        feed = json.loads(feed_p.read_text(encoding="utf-8"))
        for x in feed.get("items") or []:
            fn = (x.get("full_name") or "").lower()
            if fn:
                items.add(fn)
        for x in feed.get("corpus") or feed.get("corpus_items") or []:
            fn = (x.get("full_name") or "").lower()
            if fn:
                corpus.add(fn)
    idx = DATA / "corpus" / "index.jsonl"
    if idx.is_file():
        for line in idx.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            fn = (rec.get("full_name") or rec.get("repo") or "").lower()
            if fn:
                corpus.add(fn)
    return items, corpus


def main() -> int:
    bottom = load_bottom()
    cached = load_cached_paths()
    print(f"[load] bottom={len(bottom)} cached_paths={len(cached)}")

    pre: list[dict] = []
    dropped_star = 0
    dropped_parse = 0
    for rec in bottom.values():
        fn = rec.get("仓库全名") or ""
        name = (rec.get("名称") or fn.split("/")[-1]).strip()
        desc = (rec.get("描述") or "").strip()
        stars = int(rec.get("评星") or 0)
        if stars < 20:
            dropped_star += 1
            continue
        reason = ""
        if len(name) < 1:
            reason = "empty_name"
        elif len(desc) < 10:
            reason = "short_description"
        else:
            reason = description_shape_reason(desc, name)
        if reason:
            dropped_parse += 1
            continue
        pre.append(rec)
    print(f"[pre] star+parse ok={len(pre)} drop_star={dropped_star} drop_parse={dropped_parse}")

    need = [r for r in pre if (r.get("仓库全名") or "").lower() not in cached]
    print(f"[probe] reuse={len(pre) - len(need)} fetch={len(need)}")
    found: dict[str, str] = dict(cached)
    if need:
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {
                ex.submit(probe_root, r["仓库全名"]): r["仓库全名"]
                for r in need
            }
            done = 0
            for fut in as_completed(futs):
                fn = futs[fut]
                try:
                    sp = fut.result()
                except Exception:  # noqa: BLE001
                    sp = ""
                if sp:
                    found[fn.lower()] = sp
                done += 1
                if done % 40 == 0:
                    print(f"[probe] {done}/{len(need)} hits={sum(1 for r in need if (r.get('仓库全名') or '').lower() in found)}")

    items, corpus = feed_sets()
    candidates = []
    for rec in pre:
        fn = rec["仓库全名"]
        sp = found.get(fn.lower()) or ""
        if not sp:
            continue
        candidates.append(
            {
                "full_name": fn,
                "name": rec.get("名称") or fn.split("/")[-1],
                "description": rec.get("描述") or "",
                "keywords": rec.get("关键词") or "",
                "source": "catalog",
                "stars": int(rec.get("评星") or 0),
                "skill_path": sp,
                "wave": rec.get("_wave") or "",
                "from_new_wave": bool(rec.get("_from_new_wave")),
            }
        )
    print(f"[skill] probed_like_skill={len(candidates)}")

    passed, summary = gates.run_gates(
        candidates,
        trending_names=set(),
        min_stars=20,
        min_rel=0.15,
        interest_toks=set(),
        allowed_sources=set(gates.DEFAULT_ALLOWED_SOURCES),
        star_exempt_sources={"catalog", "corpus"},
    )
    print(f"[gates] {summary['passed']}/{summary['input']} rel={summary['rel_gate']} rejected={summary['rejected']}")

    out_rows = []
    counts = {"ITEMS": 0, "CORPUS": 0, "NEW": 0}
    new_wave = 0
    for c in passed:
        fn = (c.get("full_name") or "").lower()
        if fn in items:
            status = "ITEMS"
        elif fn in corpus:
            status = "CORPUS"
        else:
            status = "NEW"
        counts[status] += 1
        if status == "NEW" and c.get("from_new_wave"):
            new_wave += 1
        out_rows.append(
            {
                "full_name": c["full_name"],
                "stars": c.get("stars") or 0,
                "skill_path": c.get("skill_path") or "",
                "feed": status,
                "description": (c.get("description") or "")[:80],
                "wave": c.get("wave") or "",
                "from_new_wave": bool(c.get("from_new_wave")),
            }
        )
    out_rows.sort(key=lambda x: -int(x.get("stars") or 0))
    OUT.mkdir(parents=True, exist_ok=True)
    dest = OUT / "feed_candidates.json"
    dest.write_text(json.dumps(out_rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[out] {dest}")
    print(f"[feed] ITEMS={counts['ITEMS']} CORPUS={counts['CORPUS']} NEW={counts['NEW']} NEW_from_oss_wave={new_wave}")
    news = [r for r in out_rows if r["feed"] == "NEW"]
    print("[top NEW]")
    for r in news[:20]:
        print(f"  {r['stars']:>7}  {r['full_name']}  [{r['skill_path']}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
