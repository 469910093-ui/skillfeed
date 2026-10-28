"""已购技能包交付：手册、技能排序、应用介绍、知识库。

正文只在购买后由 API 下发，不写进公开页。名单来自策展表里已点名的技能。
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1] / "docs" / "packs" / "delivery"
KB_DIR = Path(__file__).resolve().parents[1] / "docs" / "packs" / "kb"
_SHELF = Path(__file__).resolve().parents[1] / "docs" / "packs" / "shelf_catalog.json"
_BAD = ("待补采", "未点名", "未写", "未拆", "逐个名未点", "笔记未")
_XHS_HOSTS = ("xiaohongshu.com", "xhslink.cn", "xhslink.com")


def shelf_status(pack_id: str) -> str:
    """返回货架 status：shelf / soon / ''（未知）。"""
    safe = (pack_id or "").strip()
    if not safe or not _SHELF.is_file():
        return ""
    try:
        data = json.loads(_SHELF.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    for raw in data.get("packs") or []:
        if isinstance(raw, dict) and str(raw.get("id") or "").strip() == safe:
            return str(raw.get("status") or "").strip()
    return ""


def is_sellable_pack(pack_id: str) -> bool:
    return shelf_status(pack_id) == "shelf"


def _is_xhs(text: str) -> bool:
    low = (text or "").lower()
    return any(host in low for host in _XHS_HOSTS)


def _strip_xhs_lines(text: str) -> str:
    kept = [line for line in (text or "").splitlines() if not _is_xhs(line)]
    return "\n".join(kept).strip()


def load_kb_markdown(pack_id: str) -> str:
    """读整理后的知识库。没有文件就返回空，调用方不要用外链凑。"""
    safe = (pack_id or "").strip()
    path = KB_DIR / f"{safe}.md"
    if not path.is_file():
        return ""
    return _strip_xhs_lines(path.read_text(encoding="utf-8"))


def kb_sections(markdown: str) -> list[dict[str, str]]:
    """按二级标题拆成可上屏的小节。不带外链。"""
    sections: list[dict[str, str]] = []
    title = ""
    buf: list[str] = []

    def flush() -> None:
        nonlocal title, buf
        body = _strip_xhs_lines("\n".join(buf))
        if title and body:
            sections.append({"title": title, "body": body})
        title = ""
        buf = []

    for line in (markdown or "").splitlines():
        if line.startswith("## "):
            flush()
            title = line[3:].strip()
            continue
        if line.startswith("# "):
            continue
        buf.append(line)
    flush()
    return sections


def merge_handbook(md: str, kb_md: str) -> str:
    """手册末尾的知识库换成整理稿，去掉小红书链接。"""
    head = _strip_xhs_lines(md)
    marker = "\n## 知识库"
    cut = head.find(marker)
    if head.startswith("## 知识库"):
        cut = 0
    elif cut >= 0:
        cut += 1
    if cut >= 0:
        head = head[:cut].rstrip()
    body = (kb_md or "").strip()
    if body.startswith("# "):
        body = body.split("\n", 1)[1].strip() if "\n" in body else ""
    if not body:
        return (head + "\n") if head else ""
    return f"{head}\n\n## 知识库\n\n{body}\n"


def load_delivery(pack_id: str) -> Optional[dict[str, Any]]:
    """读一份交付。没有材料的包返回 None，调用方不要编一份空手册。"""
    safe = (pack_id or "").strip()
    if not safe or "/" in safe or ".." in safe or not safe.replace("-", "").isalnum():
        return None
    path = ROOT / f"{safe}.json"
    if not path.is_file():
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    skills = []
    for row in raw.get("skills") or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        if not name or any(flag in name for flag in _BAD):
            continue
        skills.append({
            "order": int(row.get("order") or len(skills) + 1),
            "name": name,
            "step": str(row.get("step") or "").strip(),
            "intro": str(row.get("intro") or "").strip(),
        })
    apps = [{"name": s["name"], "intro": s["intro"]} for s in skills]
    kb_md = load_kb_markdown(safe)
    kb = kb_sections(kb_md)
    title = str(raw.get("title") or safe).strip()
    md = merge_handbook(str(raw.get("md") or ""), kb_md)
    if not skills and not md:
        return None
    return {
        "id": safe,
        "title": title,
        "md": md,
        "skills": skills,
        "apps": apps,
        "kb": kb,
        "kb_md": kb_md,
    }


def scene_triggers(doc: dict[str, Any]) -> list[str]:
    """给本机匹配用的短触发词：场景名和每个环节，不去拆介绍句。"""
    out: list[str] = []
    seen: set[str] = set()

    def add(text: str) -> None:
        token = " ".join((text or "").split())
        key = token.lower()
        if len(token) < 2 or len(token) > 32 or key in seen:
            return
        seen.add(key)
        out.append(token)

    add(str(doc.get("title") or ""))
    for row in doc.get("skills") or []:
        add(str(row.get("step") or ""))
    return out[:24]


def scene_manifest(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": doc["id"],
        "title": doc["title"],
        "triggers": scene_triggers(doc),
        "skills": [
            {
                "order": row["order"],
                "name": row["name"],
                "step": row["step"],
                "intro": row["intro"],
            }
            for row in doc["skills"]
        ],
    }


INSTALL_NOTE = (
    "在终端把这个压缩包装进本机：\n"
    "python ~/.skill-picker/skillpick.py install-scene 压缩包路径 --yes\n"
    "\n"
    "装好后，你再说手头的任务，会从这套场景里推荐一个技能。你点选后才用。\n"
)


def build_package(pack_id: str) -> Optional[tuple[str, bytes]]:
    """已购场景的安装包：手册、技能排序、安装说明、给本机安装的 scene.json。"""
    doc = load_delivery(pack_id)
    if doc is None:
        return None
    skills = []
    for row in doc["skills"]:
        skills.append(
            f"{row['order']}. {row['name']}\n{row['step']}\n{row['intro']}".strip()
        )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("手册.md", doc["md"] + ("\n" if not doc["md"].endswith("\n") else ""))
        if doc.get("kb_md"):
            zf.writestr(
                "知识库.md",
                doc["kb_md"] + ("\n" if not str(doc["kb_md"]).endswith("\n") else ""),
            )
        zf.writestr("技能排序.txt", "\n\n".join(skills) + "\n")
        zf.writestr("安装说明.txt", INSTALL_NOTE)
        zf.writestr(
            "scene.json",
            json.dumps(scene_manifest(doc), ensure_ascii=False, indent=2) + "\n",
        )
    return f"skillfeeder-{doc['id']}.zip", buf.getvalue()
