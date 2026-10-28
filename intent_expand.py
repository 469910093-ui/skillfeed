"""意图搜索的近义扩展（前后端共用）。

用户常输短口语（「生图」「去AI味」），语料里却写英文 skill 名或场景标签。
这里用「意图簇」把短词映射到真实会在卡片文案 / 场景标签里出现的 token。

硬约束（与 scene.py 同源）：
- 禁止裸英文短词误伤（如裸 image / design / art）
- 扩展 token 必须能在语料里当子串命中，禁止造假二元组
- 前端 intentMatch 的「强词」单点即可召回；弱扩展要靠 ≥2 命中
"""

from __future__ import annotations

from typing import Any

# 每个簇：
#   id        — 稳定标识
#   canon     — 压缩后显示在搜索框的规范短词（跟语言）
#   triggers  — 用户输入命中任一即激活本簇（小写比对）
#   expand    — 参与匹配的扩展 token（小写）
#   strong    — 单点命中即可召回的强词（须 ⊆ expand ∪ triggers ∪ canon）
#   phrases   — 灌进 INTENT_PHRASES，让 compressIntent 能认出
#   scenes    — 命中本簇时推断的 (一级, 二级)；搜索时同场景的卡加分
CLUSTERS: list[dict[str, Any]] = [
    {
        "id": "deslop",
        "scenes": (("content", "writing"),),
        "canon": {"zh": "去AI味", "en": "stop-slop"},
        "triggers": (
            "去ai味", "去ai", "ai味", "stop-slop", "slop", "人味", "润色",
        ),
        "expand": (
            "slop", "stop-slop", "ai writing", "ai味", "去ai", "去ai味",
            "写作", "文案", "润色", "human",
        ),
        "strong": (
            "stop-slop", "slop", "ai味", "去ai", "去ai味",
        ),
        "phrases": ("去ai味", "stop-slop", "ai味", "去ai"),
    },
    {
        "id": "design",
        "scenes": (("design", "figma"),),
        "canon": {"zh": "产品设计", "en": "product design"},
        "triggers": (
            "产品设计", "交互设计", "视觉设计", "frontend-design", "web-design",
            "ui ux", "figma", "shadcn", "taste", "设计",
        ),
        "expand": (
            "frontend-design", "web-design", "web-design-guidelines", "figma",
            "ui", "ux", "design", "shadcn", "hallmark", "taste-skill",
            "产品设计", "交互", "界面", "prototype", "design system",
            "canvas-design",
        ),
        "strong": (
            "hallmark", "frontend-design", "web-design", "figma", "shadcn",
            "taste-skill", "产品设计",
        ),
        "phrases": (
            "产品设计", "交互设计", "视觉设计", "figma", "设计", "ui", "ux",
        ),
    },
    {
        # 「生图」口语 → 出图/配图/视觉海报/canvas-design 等真实解法。
        # 不吸 frontend-design / figma（那是产品设计簇）；不放裸 image。
        "id": "imagen",
        "scenes": (("design", "visual"), ("design", "chart")),
        "canon": {"zh": "生图", "en": "image-gen"},
        "triggers": (
            "生图", "出图", "画图", "绘图", "配图", "生成图片", "生成图",
            "text-to-image", "image-gen", "imagegen", "image generation",
            "generate image", "generate images", "文生图", "ai绘画", "ai画画",
            "图片", "图像",
            # 日 / 韩：正文是多语的，查询也可能是
            "画像生成", "イラスト", "ポスター", "이미지 생성", "그림",
        ),
        "expand": (
            "生图", "出图", "画图", "绘图", "配图", "生成图片", "文生图",
            "海报", "插图", "封面", "信息图", "视觉海报", "图片", "图像",
            "illustration", "infographic", "text-to-image",
            "image-gen", "imagegen", "image_gen", "image generation",
            "generate image", "generate images", "poster",
            "midjourney", "dalle", "dall-e", "flux", "comfyui",
            "canvas-design", "brandkit", "brand-guidelines", "theme-factory",
            "nanobanana", "nano banana",
            "画像生成", "イラスト", "ポスター", "이미지",
        ),
        "strong": (
            "生图", "出图", "画图", "绘图", "配图", "生成图片", "文生图",
            "海报", "插图", "信息图", "视觉海报",
            "illustration", "infographic", "text-to-image",
            "image-gen", "imagegen", "image_gen", "image generation",
            "generate image", "generate images",
            "midjourney", "comfyui",
            "canvas-design", "brandkit", "brand-guidelines", "theme-factory",
            "nanobanana",
        ),
        "phrases": (
            "生成图片", "text-to-image", "image generation", "image-gen",
            "imagegen", "文生图", "ai绘画", "生图", "出图", "画图", "绘图",
            "配图",
        ),
    },
    {
        # 「画架构图」要的是出图，不是重构代码架构
        "id": "diagram",
        "scenes": (("design", "chart"),),
        "canon": {"zh": "架构图", "en": "diagram"},
        "triggers": (
            "架构图", "流程图", "思维导图", "示意图", "时序图", "关系图", "拓扑图",
            "diagram", "flowchart", "mind map", "mindmap", "mermaid",
            "excalidraw", "drawio", "draw.io", "plantuml",
            "図解", "フローチャート", "다이어그램",
        ),
        "expand": (
            "架构图", "流程图", "思维导图", "示意图", "图解", "白板", "可视化",
            "diagram", "flowchart", "mind map", "mermaid", "excalidraw",
            "drawio", "plantuml", "whiteboard", "infographic",
        ),
        "strong": (
            "架构图", "流程图", "思维导图", "示意图", "图解",
            "diagram", "flowchart", "mermaid", "excalidraw", "drawio", "plantuml",
        ),
        "phrases": ("架构图", "流程图", "思维导图", "diagram", "flowchart", "mermaid"),
    },
    {
        # 中英互通：中文「周报」够到英文 SKILL.md 里的 weekly report / retro
        "id": "weekly",
        "scenes": (("data-review", "weekly"),),
        "canon": {"zh": "周报", "en": "weekly report"},
        "triggers": (
            "周报", "周复盘", "周总结", "月报", "weekly report", "weekly review",
            "status report", "週報", "주간 보고",
        ),
        "expand": (
            "周报", "复盘", "周总结", "月报", "weekly report", "weekly review",
            "weekly update", "status report", "retro", "retrospective",
            "环比", "week over week",
        ),
        "strong": (
            "周报", "周总结", "weekly report", "weekly review", "weekly update",
            "status report", "retrospective",
        ),
        "phrases": ("周报", "月报", "weekly report"),
    },
]


def all_phrases() -> list[str]:
    """额外灌进前端 INTENT_PHRASES 的词（去重，长的优先由前端再 sort）。"""
    seen: set[str] = set()
    out: list[str] = []
    for cluster in CLUSTERS:
        for p in cluster.get("phrases") or ():
            key = str(p).lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(str(p))
    return out


def all_strong() -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for cluster in CLUSTERS:
        for t in cluster.get("strong") or ():
            key = str(t).lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(key)
    return out


def clusters_for_js() -> list[dict[str, Any]]:
    """前端 INTENT_EXPAND 用的精简结构。"""
    rows = []
    for cluster in CLUSTERS:
        rows.append({
            "id": cluster["id"],
            "canon": dict(cluster.get("canon") or {}),
            "triggers": [str(t).lower() for t in (cluster.get("triggers") or ())],
            "expand": [str(t).lower() for t in (cluster.get("expand") or ())],
            "strong": [str(t).lower() for t in (cluster.get("strong") or ())],
        })
    return rows


def expand_terms(query: str) -> set[str]:
    """把查询扩成匹配用 token 集合（含原文小写）。供 geo / API 打分。"""
    raw = (query or "").strip().lower()
    if not raw:
        return set()
    compact = raw.replace(" ", "")
    out: set[str] = {raw}
    if compact and compact != raw:
        out.add(compact)
    for part in raw.split():
        if len(part) >= 2:
            out.add(part)
    for cluster in CLUSTERS:
        triggers = [str(t).lower() for t in (cluster.get("triggers") or ())]
        hit = False
        for trig in triggers:
            if not trig:
                continue
            if " " in trig:
                if trig in raw:
                    hit = True
                    break
            elif trig in compact or trig in raw:
                hit = True
                break
        if not hit:
            continue
        canon = cluster.get("canon") or {}
        for v in canon.values():
            if v:
                out.add(str(v).lower())
        for t in cluster.get("expand") or ():
            if t:
                out.add(str(t).lower())
    return {t for t in out if len(t) >= 2}


def score_blob(blob: str, query: str) -> float:
    """对已拼好的小写 blob 打意图分；无命中返回 0。"""
    q = (query or "").strip().lower()
    if not q:
        return 0.0
    text = (blob or "").lower()
    score = 0.0
    if q in text:
        score += 2.0
    terms = expand_terms(q)
    if not terms:
        return score
    hits = sum(1 for t in terms if t in text)
    if hits:
        score += hits / max(len(terms), 1) + min(hits, 5) * 0.15
    return score
