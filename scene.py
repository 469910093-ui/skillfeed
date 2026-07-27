"""Skills 场景一/二级分类打标。"""

from __future__ import annotations

import re
from typing import Optional

# 一级：id → 中文名
SCENES: list[tuple[str, str]] = [
    ("content", "内容创作"),
    ("design", "设计与视觉"),
    ("data-review", "数据与复盘"),
    ("engineering", "工程开发"),
    ("quality", "Bug与质量"),
    ("collab", "协作办公"),
    ("research", "研究与知识"),
    ("agent-tooling", "Agent工具链"),
    ("biz-vertical", "业务垂直"),
    ("other", "其他"),
]

SCENE_LABELS = {sid: label for sid, label in SCENES}

# 二级：parent → [(id, label, keywords...)]
SCENES_L2: dict[str, list[tuple[str, str, tuple[str, ...]]]] = {
    "content": [
        ("writing", "写作润色", ("写作", "文案", "润色", "stop-slop", "去ai味", "copy", "writing")),
        ("short-video", "短视频口播", ("短视频", "口播", "剪辑", "脚本", "viral", "种草", "抖音")),
        ("topic", "选题策划", ("选题", "选题库", "热点", "内容策划")),
        ("podcast", "播客音频", ("播客", "podcast", "音频", "口播稿")),
    ],
    "design": [
        ("figma", "Figma/UI", ("figma", "ui", "界面", "design system")),
        ("slides", "幻灯片PPT", ("ppt", "幻灯", "slide", "deck", "演示")),
        ("chart", "图表信息图", ("图表", "infographic", "白板", "可视化", "antv")),
        ("visual", "视觉海报", ("海报", "配色", "视觉", "品牌")),
    ],
    "data-review": [
        ("weekly", "周报复盘", ("周报", "复盘", "wow", "mom", "活动复盘")),
        ("bi", "BI指标", ("bi", "指标", "gmv", "dashboard", "拉数", "报表")),
        ("analytics", "分析解读", ("analytics", "数据分析", "洞察")),
    ],
    "engineering": [
        ("refactor", "重构架构", ("重构", "架构", "refactor", "codebase")),
        ("less-code", "少写代码", ("ponytail", "少写代码", "过度工程")),
        ("sdk", "SDK/API", ("sdk", "api", "库", "typescript", "python")),
        ("coding", "编码实现", ("开发", "编程", "实现", "coding")),
    ],
    "quality": [
        ("debug", "调试排错", ("debug", "调试", "排错", "bug")),
        ("testing", "测试验证", ("测试", "unittest", "qa", "验证", "regression")),
        ("review", "Code Review", ("code review", "review", "门禁", "lint")),
    ],
    "collab": [
        ("feishu", "飞书协作", ("飞书", "lark", "审批")),
        ("notion", "Notion/文档", ("notion", "文档协作")),
        ("meeting", "会议纪要", ("会议", "纪要", "todo", "任务", "calendar")),
    ],
    "research": [
        ("academic", "学术文献", ("学术", "文献", "论文", "academic", "citation")),
        ("deep-read", "精读解读", ("精读", "read-anything", "解读")),
        ("notes", "笔记知识库", ("笔记库", "zettel", "知识库", "第二大脑")),
    ],
    "agent-tooling": [
        ("skill-mgmt", "Skill管理", ("skill-picker", "skill-feed", "skills", "skill")),
        ("mcp", "MCP工具", ("mcp", "model context")),
        ("prompt", "提示词工作流", ("prompt", "提示词", "工作流", "workflow")),
        ("agent-runtime", "Agent运行时", ("agent", "openclaw", "codex", "claude code")),
    ],
    "biz-vertical": [
        ("ecommerce", "电商经营", ("电商", "抖店", "淘宝", "天猫")),
        ("travel", "出行旅游", ("出行", "hotel", "flight", "火车", "旅游")),
        ("marketing", "营销投放", ("营销", "投放", "广告", "campaign")),
        ("pet", "宠物辅具", ("宠物", "辅具", "轮椅")),
    ],
    "other": [
        ("misc", "未细分", ()),
    ],
}

SCENE_L2_LABELS: dict[str, str] = {}
for _parent, children in SCENES_L2.items():
    for cid, label, _kws in children:
        SCENE_L2_LABELS[cid] = label

# frontmatter category / tags 别名 → (L1, optional L2)
FM_ALIASES: dict[str, tuple[str, Optional[str]]] = {
    "content": ("content", None),
    "writing": ("content", "writing"),
    "copywriting": ("content", "writing"),
    "video": ("content", "short-video"),
    "short-video": ("content", "short-video"),
    "podcast": ("content", "podcast"),
    "design": ("design", None),
    "visual": ("design", "visual"),
    "figma": ("design", "figma"),
    "slides": ("design", "slides"),
    "ppt": ("design", "slides"),
    "data": ("data-review", None),
    "analytics": ("data-review", "analytics"),
    "review": ("data-review", "weekly"),
    "bi": ("data-review", "bi"),
    "weekly": ("data-review", "weekly"),
    "engineering": ("engineering", None),
    "coding": ("engineering", "coding"),
    "dev": ("engineering", "coding"),
    "refactor": ("engineering", "refactor"),
    "quality": ("quality", None),
    "debug": ("quality", "debug"),
    "testing": ("quality", "testing"),
    "qa": ("quality", "testing"),
    "collab": ("collab", None),
    "office": ("collab", None),
    "feishu": ("collab", "feishu"),
    "lark": ("collab", "feishu"),
    "notion": ("collab", "notion"),
    "research": ("research", None),
    "academic": ("research", "academic"),
    "knowledge": ("research", "notes"),
    "agent": ("agent-tooling", "agent-runtime"),
    "mcp": ("agent-tooling", "mcp"),
    "skill": ("agent-tooling", "skill-mgmt"),
    "tooling": ("agent-tooling", None),
    "biz": ("biz-vertical", None),
    "ecommerce": ("biz-vertical", "ecommerce"),
    "marketing": ("biz-vertical", "marketing"),
    "travel": ("biz-vertical", "travel"),
}

# 一级关键词规则（命中加分）
RULES: list[tuple[str, tuple[str, ...]]] = [
    ("content", (
        "文案", "短视频", "口播", "选题", "写作", "去ai味", "stop-slop", "viral",
        "writing", "copy", "script", "播客", "种草", "内容创作",
    )),
    ("design", (
        "figma", "图表", "白板", "ppt", "幻灯", "视觉", "infographic", "slide",
        "design", "ui", "海报", "配色",
    )),
    ("data-review", (
        "周报", "复盘", "bi", "指标", "gmv", "wow", "mom", "dashboard", "拉数",
        "数据", "analytics", "报表", "活动复盘",
    )),
    ("engineering", (
        "重构", "架构", "ponytail", "少写代码", "codebase", "refactor", "api",
        "开发", "编程", "typescript", "python 库", "sdk",
    )),
    ("quality", (
        "debug", "调试", "测试", "unittest", "code review", "门禁", "bug",
        "qa", "验证", "lint", "regression",
    )),
    ("collab", (
        "飞书", "lark", "notion", "会议", "纪要", "任务", "calendar", "审批",
        "协作", "office", "文档协作",
    )),
    ("research", (
        "学术", "文献", "精读", "论文", "academic", "research", "笔记库",
        "zettel", "知识库", "read-anything",
    )),
    ("agent-tooling", (
        "skill", "skills", "mcp", "agent", "prompt", "工作流", "cursor skill",
        "claude skill", "提示词", "tooling", "skill-picker", "skill-feed",
    )),
    ("biz-vertical", (
        "电商", "抖音", "抖店", "出行", "hotel", "flight", "营销", "投放",
        "宠物", "辅具", "垂直",
    )),
]


def _hay(item: dict) -> str:
    fm = item.get("frontmatter") or {}
    parts = [
        item.get("name") or "",
        item.get("description") or "",
        item.get("keywords") or "",
        item.get("body_preview") or "",
        item.get("repo_description") or "",
        item.get("hg_section") or "",
        str(fm.get("category") or ""),
        str(fm.get("tags") or ""),
        str(fm.get("scene_l2") or ""),
    ]
    return " ".join(parts).lower()


def tag_scene_l2(item: dict, scene_id: str) -> tuple[str, float, str]:
    """在已定一级下打二级。"""
    fm = item.get("frontmatter") or {}
    for key in ("scene_l2", "subcategory", "tags"):
        raw = str(fm.get(key) or "").strip().lower()
        if not raw:
            continue
        for part in re.split(r"[,|/，、\s]+", raw):
            part = part.strip()
            if part in SCENE_L2_LABELS:
                # 校验归属
                for cid, _label, _kws in SCENES_L2.get(scene_id, []):
                    if cid == part:
                        return part, 0.9, f"frontmatter:{key}={part}"
            alias = FM_ALIASES.get(part)
            if alias and alias[0] == scene_id and alias[1]:
                return alias[1], 0.88, f"frontmatter:{key}={part}"

    hay = _hay(item)
    best_id = ""
    best_score = 0
    best_hits: list[str] = []
    for cid, _label, kws in SCENES_L2.get(scene_id, []):
        score = 0
        hits: list[str] = []
        for kw in kws:
            if kw.lower() in hay:
                score += 1
                if len(hits) < 3:
                    hits.append(kw)
        if score > best_score:
            best_score = score
            best_id = cid
            best_hits = hits
    if best_score <= 0:
        # 默认取该一级下第一项或 misc
        children = SCENES_L2.get(scene_id) or [("misc", "未细分", ())]
        return children[0][0], 0.25, "default-l2"
    conf = min(0.92, 0.4 + 0.15 * best_score)
    return best_id, round(conf, 2), f"l2:{','.join(best_hits[:3])}"


def tag_scene(item: dict) -> tuple[str, float, str]:
    """
    返回 (scene_id, confidence 0-1, why)。
    优先 frontmatter，再关键词打分。
    """
    fm = item.get("frontmatter") or {}
    for key in ("category", "scene", "tags"):
        raw = str(fm.get(key) or "").strip().lower()
        if not raw:
            continue
        for part in re.split(r"[,|/，、\s]+", raw):
            part = part.strip()
            if part in FM_ALIASES:
                sid, _l2 = FM_ALIASES[part]
                return sid, 0.9, f"frontmatter:{key}={part}"
            if part in SCENE_LABELS:
                return part, 0.9, f"frontmatter:{key}={part}"

    hay = _hay(item)
    scores: dict[str, int] = {sid: 0 for sid, _ in SCENES if sid != "other"}
    hits: dict[str, list[str]] = {sid: [] for sid in scores}

    for sid, kws in RULES:
        for kw in kws:
            if kw.lower() in hay:
                scores[sid] += 1
                if len(hits[sid]) < 4:
                    hits[sid].append(kw)

    if (item.get("hg_section") or "").strip().lower() == "skills":
        other_hit = any(v > 0 for s, v in scores.items() if s != "agent-tooling")
        if not other_hit:
            scores["agent-tooling"] += 1
            hits["agent-tooling"].append("hg:Skills")

    best = max(scores.items(), key=lambda x: x[1])
    if best[1] <= 0:
        return "other", 0.2, "no rule hit"
    top = best[1]
    tied = sorted([s for s, v in scores.items() if v == top])
    if len(tied) > 1 and "agent-tooling" in tied:
        tied = [s for s in tied if s != "agent-tooling"] or tied
    sid = tied[0]
    conf = min(0.95, 0.35 + 0.15 * top)
    why = f"rules:{','.join(hits[sid][:4])}"
    return sid, round(conf, 2), why


def apply_scene(item: dict) -> dict:
    out = dict(item)
    sid, conf, why = tag_scene(out)
    out["scene"] = sid
    out["scene_label"] = SCENE_LABELS.get(sid, sid)
    out["scene_confidence"] = conf
    out["scene_why"] = why
    l2, l2_conf, l2_why = tag_scene_l2(out, sid)
    out["scene_l2"] = l2
    out["scene_l2_label"] = SCENE_L2_LABELS.get(l2, l2)
    out["scene_l2_confidence"] = l2_conf
    out["scene_l2_why"] = l2_why
    return out


def scene_chips() -> list[dict]:
    return [{"id": sid, "label": label} for sid, label in SCENES]


def scene_l2_tree() -> dict[str, list[dict]]:
    """供 Feed 前端：一级 → 二级 chips。"""
    tree: dict[str, list[dict]] = {}
    for parent, children in SCENES_L2.items():
        tree[parent] = [{"id": cid, "label": label} for cid, label, _ in children]
    return tree
