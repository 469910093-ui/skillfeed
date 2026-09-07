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
#
# 二级和一级 RULES 走同一套子串包含匹配，所以同一条铁律在这里同样成立：
# 不放长度 < 4 的裸英文短词，一律换成带空格/斜杠的词组。实测（766 篇语料）
# 被清掉的地雷及其真实吞噬者：
#   ui  → build 131 次、guidelines 74 次、building 51 次，87% 是误命中
#   bi  → accessibility / capabilities / mobile / bitable，真词命中数为 0
#   ux  → linux 34 次、nuxt 17 次、luxury，80% 是误命中
#   wow → 唯一命中是「wow experience」（惊喜感），不是 week-over-week
#   mom → 只命中 moment(s)，真词命中数为 0
#   qa  → 语料里唯一真词命中被 "测试" 覆盖，留着只是留个 2 字符的雷
#   bom → 当前语料尚无污染，但它是 bomb/bombay 的子串，属于早晚要炸的雷；
#         改用 "bom management"（6 篇）/"物料清单" 后召回一篇没少
# 少数 < 4 的短词刻意保留（ppt/sdk/sql/aws/pcb/bug/mcp/api/gmv）：实测吞掉
# 它们的长词语义仍然正确（pptx 仍是 PPT，mysql 仍是数据库），白名单和理由
# 见 tests/test_search_rank_scene.py 的 SHORT_WORD_ALLOWLIST。
SCENES_L2: dict[str, list[tuple[str, str, tuple[str, ...]]]] = {
    "content": [
        ("writing", "写作润色", (
            "写作", "文案", "润色", "stop-slop", "去ai味", "copywriting",
        )),
        ("short-video", "短视频口播", ("短视频", "口播", "剪辑", "脚本", "viral", "种草", "抖音")),
        ("topic", "选题策划", ("选题", "选题库", "热点", "内容策划")),
        ("podcast", "播客音频", ("播客", "podcast", "音频", "口播稿")),
        ("social", "社媒图文", (
            "小红书", "xiaohongshu", "rednote", "公众号", "笔记", "推文",
            "thread", "爆款", "标题",
        )),
    ],
    "design": [
        ("figma", "Figma/UI", (
            "figma", "界面", "交互", "产品设计", "design system",
            # 中英文混排的空格写法不统一，"ui 设计" 和 "ui设计" 互不为子串，
            # 两种都得列，否则只写一种会漏掉另一半语料。
            "ui 设计", "ui设计", "ui design", "ui/ux", "ux/ui",
            "ux 设计", "ux设计", "ux design", "user interface", "user experience",
            "ui mockup", "ui 组件",
            # 连字符后缀是 UI 组件库/设计 skill 的命名习惯（minimalist-ui、
            # brutalist-ui、frontend-ui-engineering），4 篇命中零污染。
            # 反过来 "/ui" 不能用：它会命中 evdev/uinput 这种设备节点路径。
            "-ui",
            "frontend-design", "web-design", "shadcn", "prototype", "wireframe",
            "taste-skill", "hallmark",
        )),
        ("slides", "幻灯片PPT", ("ppt", "幻灯", "slide", "deck", "演示")),
        ("chart", "图表信息图", ("图表", "infographic", "白板", "可视化", "antv")),
        ("visual", "视觉海报", (
            "海报", "配色", "视觉", "品牌", "canvas-design", "brand-guidelines",
            "theme-factory", "taste", "taste-skill",
        )),
        # 一级 RULES 早就认动画方向（动画/animation/motion design/remotion/动效），
        # 但二级没有落点，remotion 系 7 条 + hyperframes 系 + view-transitions
        # 全掉进无二级。这里补上。
        # 挑词时被否掉的候选，理由都是实测出来的：
        #   motion   → remotion 118 次、emotional 5 次，58% 不是独立词；
        #              promotion 更是上一轮一级修复踩过的雷。改用 motion design 等词组
        #   tween    → 19 篇命中 100% 来自 between，一次真词都没有
        #   gif      → 语料里零污染，但 gift/gifted 是现成的英文长词，不值得赌；
        #              唯一那条 slack-gif-creator 自述「轻量动画 gif」，动画已经接住
        #   帧       → 15 篇命中里 14 篇确实是视频帧/抽帧/帧率，但多数是字幕、
        #              视频转写工具（一级落在内容创作，根本走不到这里），
        #              且有「脑帧」这种译名噪音。只收精确的「关键帧」
        #   渲染     → 28 篇里大量是「重复渲染」「样式渲染」（React 性能、排版），
        #              跟动效无关。只收「视频渲染」
        #   timeline → 命中的是照片时间轴、地图时间轴、录屏剪辑时间轴，语义太杂
        #   easing   → 被 pleasing / releasing 吃掉一半。改用「缓动」
        ("motion", "动效动画", (
            "动画", "动效", "animation", "motion design", "motion graphics",
            "framer motion", "remotion", "hyperframes", "gsap", "lottie",
            "after effects", "keyframe", "关键帧", "view transition",
            "缓动", "视频渲染",
        )),
    ],
    "data-review": [
        # 环比/同比就是 WoW/MoM 的中文说法；英文侧写全称，连字符写法也要列。
        #
        # 「复盘」是本轮收窄的：它的泛用义是「回顾/反思」，语料里两条命中
        # （think 的 who_for_zh「复盘主导者」、stock_analyzer 的「市场复盘」）
        # 都不是周报口径的复盘。收成词组后这个桶会变 0 条，前端 countL2() > 0
        # 会自动隐藏空 chip，零用户成本。桶本身保留：周报/环比/WoW/MoM 是仓库
        # 主人自己的工作词汇，他自己的 skill 进 feed 时要靠这个桶亮起来。
        ("weekly", "周报复盘", (
            "周报", "复盘报告", "活动复盘", "周报复盘", "月度复盘", "季度复盘",
            "环比", "同比增长",
            "week over week", "week-over-week",
            "month over month", "month-over-month",
        )),
        # 桶 id 保留 "bi" 不动：已发布的 feed.json 里存着 scene_l2="bi"，
        # feedback.jsonl 的偏好权重也按这个 id 累计，改 id 会让历史数据对不上。
        # 但展示标签必须改：语料实测 "bi"/"商业智能"/"power bi"/"business
        # intelligence" 全部 0 命中，真实召回 100% 来自 指标/dashboard/报表。
        # 挂「BI」的徽标等于向用户承诺一个语料里不存在的东西。
        ("bi", "指标看板", (
            "指标", "gmv", "dashboard", "拉数", "报表",
            "商业智能", "business intelligence", "power bi", "bi 报表", "bi 看板",
        )),
        ("analytics", "分析解读", (
            "analytics", "数据分析", "洞察", "协方差", "covariance",
            "时间序列", "time series", "统计", "forecast", "预测",
            "a/b", "ab test", "实验",
        )),
    ],
    "engineering": [
        ("refactor", "重构架构", ("重构", "架构", "refactor", "codebase")),
        ("less-code", "少写代码", ("ponytail", "少写代码", "过度工程")),
        ("sdk", "SDK/API", ("sdk", "api", "库", "typescript", "python")),
        ("infra", "云与部署", (
            "azure", "aws", "虚拟机", "部署", "deploy", "docker",
            "kubernetes", "terraform", "迁移", "supabase", "postgres",
            "数据库", "database", "sql",
        )),
        ("hardware", "硬件固件", (
            "pcb", "kicad", "固件", "firmware", "嵌入式",
            "物料清单", "bill of materials", "bom management", "bom 管理",
        )),
        ("coding", "编码实现", ("开发", "编程", "实现", "coding")),
    ],
    "quality": [
        ("debug", "调试排错", ("debug", "调试", "排错", "bug")),
        ("testing", "测试验证", (
            "测试", "unittest", "验证", "regression",
            "qa 测试", "quality assurance",
        )),
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
        ("notes", "笔记知识库", (
            "笔记库", "zettel", "知识库", "第二大脑", "obsidian", "知识图谱",
        )),
    ],
    "agent-tooling": [
        # 同一级规则：不放裸词 skill/skills，否则整个语料都会落进这里
        ("skill-mgmt", "Skill管理", ("skill-picker", "skill-feed", "skill 管理", "marketplace")),
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

SCENE_LABELS_EN: dict[str, str] = {
    "content": "Content",
    "design": "Design & Visual",
    "data-review": "Data & Review",
    "engineering": "Engineering",
    "quality": "Bugs & Quality",
    "collab": "Collaboration",
    "research": "Research",
    "agent-tooling": "Agent Tooling",
    "biz-vertical": "Business",
    "other": "Other",
}

SCENE_L2_LABELS_EN: dict[str, str] = {
    "writing": "Writing",
    "short-video": "Short Video",
    "topic": "Topic Planning",
    "podcast": "Podcast",
    "social": "Social Posts",
    "infra": "Cloud & Deploy",
    "hardware": "Hardware",
    "figma": "Figma / UI",
    "slides": "Slides",
    "chart": "Charts",
    "visual": "Visual & Brand",
    "motion": "Motion & Animation",
    "weekly": "Weekly Review",
    "bi": "Metrics & Dashboards",
    "analytics": "Analytics",
    "refactor": "Refactoring",
    "less-code": "Less Code",
    "sdk": "SDK / API",
    "coding": "Coding",
    "debug": "Debugging",
    "testing": "Testing",
    "review": "Code Review",
    "feishu": "Feishu",
    "notion": "Notion / Docs",
    "meeting": "Meetings",
    "academic": "Academic",
    "deep-read": "Deep Reading",
    "notes": "Notes & PKM",
    "skill-mgmt": "Skill Management",
    "mcp": "MCP Tools",
    "prompt": "Prompt Workflow",
    "agent-runtime": "Agent Runtime",
    "ecommerce": "E-commerce",
    "travel": "Travel",
    "marketing": "Marketing",
    "pet": "Pet Mobility",
    "misc": "Uncategorized",
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
    "motion": ("design", "motion"),
    "animation": ("design", "motion"),
    "data": ("data-review", None),
    "analytics": ("data-review", "analytics"),
    "review": ("data-review", "weekly"),
    "bi": ("data-review", "bi"),
    "metrics": ("data-review", "bi"),
    "dashboard": ("data-review", "bi"),
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
    # 匹配是子串包含，所以裸英文短词很危险：
    #   "script" 会命中 JavaScript / TypeScript，"writing" 会命中
    #   "before writing code"，"copy" 会命中 copyright。一律换成词组。
    ("content", (
        "文案", "短视频", "口播", "选题", "写作", "去ai味", "stop-slop", "viral",
        "copywriting", "ghostwriting", "口播稿", "分镜脚本", "播客", "种草",
        "内容创作", "小红书", "xiaohongshu", "rednote", "公众号", "抖音",
        "tiktok", "爆款", "推文", "newsletter", "字幕", "subtitle", "剪辑",
    )),
    # 同上：裸 "ui" 命中 build/guide/require，裸 "motion" 命中 promotion，
    # 裸 "design" 命中一切工程文档里的 "designed to"。
    ("design", (
        "figma", "图表", "白板", "ppt", "幻灯", "视觉", "infographic", "slide",
        # 这批词形和 SCENES_L2 的 figma 桶保持一致：上一轮只在二级补了
        # "ui设计"（无空格）这类写法，一级漏了，结果 image-to-code 的
        # 「前端工程师、ui设计师、营销建站者」只匹配到 营销，被判成业务垂直。
        "ui 设计", "ui设计", "ui design", "ui/ux", "ux/ui", "ux设计", "ux design",
        "user interface", "user experience", "ui mockup", "ui 组件",
        "海报", "配色", "产品设计",
        "交互设计", "视觉设计", "design system", "界面",
        "frontend-design", "web-design", "shadcn", "prototype", "wireframe",
        "taste-skill", "hallmark",
        "动画", "animation", "motion design", "framer motion", "动效",
        # 和二级 motion 桶保持一致：只在二级认得的框架名，一级要是不认，
        # 那些只靠框架名说明自己的 skill 连 design 这一级都进不来，
        # 二级桶对它们等于不存在（hyperframes-core 就差点这样）。
        "remotion", "hyperframes", "gsap", "lottie", "渲染", "分镜", "storyboard",
    )),
    # 同上：裸 "wow" 命中的是「wow experience」（惊喜感），裸 "mom" 只命中
    # moment(s)，两者的真词命中数都是 0。WoW/MoM 用中文「环比/同比」和英文全称表达。
    ("data-review", (
        "周报", "复盘", "指标", "gmv", "dashboard", "拉数",
        "环比", "同比增长", "week over week", "week-over-week",
        "month over month", "month-over-month",
        "数据", "analytics", "报表", "活动复盘", "商业智能",
        "协方差", "covariance", "时间序列", "time series", "统计", "forecast",
        "a/b", "ab test", "实验",
    )),
    ("engineering", (
        "重构", "架构", "ponytail", "少写代码", "codebase", "refactor",
        "开发", "编程", "typescript", "python 库", "sdk",
        "rest api", "openapi", "graphql", "接口设计",
        "部署", "deploy", "docker", "kubernetes", "数据库", "database", "sql",
        "postgres", "supabase", "azure", "aws", "虚拟机", "迁移", "terraform",
        "抓取", "scrape", "crawl", "pcb", "kicad", "物料清单", "固件", "firmware",
    )),
    ("quality", (
        "debug", "调试", "测试", "unittest", "code review", "门禁", "bug",
        "验证", "lint", "regression",
    )),
    ("collab", (
        "飞书", "lark", "notion", "会议", "纪要", "任务管理", "待办", "calendar", "审批",
        "协作", "office", "文档协作", "docx", "word 文档", "excel", "邮件",
    )),
    ("research", (
        "学术", "文献", "精读", "论文", "academic", "调研", "笔记库",
        "zettel", "知识库", "read-anything", "obsidian", "知识图谱", "第二大脑",
    )),
    # 注意：这里刻意不放裸词 "skill"/"skills"。
    # 语料里 100% 的条目都是 skill，且匹配面含 skill_path（`skills/x/SKILL.md`
    # 小写后必然命中），裸词区分度为零，会把所有卡片吸到 Agent工具链。
    ("agent-tooling", (
        "mcp", "model context", "agent", "subagent", "prompt", "提示词",
        "工作流", "workflow", "tooling", "cursor skill", "claude skill",
        "claude code", "openclaw", "codex", "skill-picker", "skill-feed",
    )),
    # 裸词地雷不只出在英文上：「垂直」的business 义只在「垂直领域/垂直行业」里，
    # 语料 4 次命中有 3 次是别的意思——「垂直切片工单」（vertical slice，工程）、
    # 「垂直 niche 标签」「精准垂直标签」（小红书标签，内容）。收成词组后
    # to-tickets 从业务垂直回到工程开发，唯一的真词命中（「垂直领域领导者」）没丢。
    ("biz-vertical", (
        "电商", "抖店", "淘宝", "天猫", "出行", "hotel", "flight", "营销",
        "投放", "宠物", "辅具", "垂直领域", "垂直行业",
    )),
]


# ── 字段权重 ─────────────────────────────────────────────────────────────
# 本该进 config_defaults.json，因该文件正被并发改动占用，暂放此处。
#
# 改造前这里是 _hay()：把十几个字段拼成一个大字符串，所有关键词在同一个串上
# 做子串匹配。等权拼串的后果是「一个词出现在 name 里，和出现在 700 字正文的
# 第 600 字，得分完全一样」。实测 388 条真实语料（撇开该字段后判定会变的条数）：
#   撇开 body_preview → 一级翻 42 条(10.8%)、二级翻 64 条(16.5%)
#   撇开 who_for_zh   → 一级翻 50 条(12.9%)、二级翻 63 条(16.2%)
#   两个都撇开        → 一级翻 89 条(22.9%)、二级翻 114 条(29.4%)
# 也就是近四分之一的行业标签由这两个低信噪比字段单方面决定。
#
# who_for_zh 写的是**受众职业**而不是功能：「适合 XX 开发者」把 30 多条吸进
# 工程开发，「适合营销建站者」曾把 image-to-code 判成营销，「复盘主导者」把
# think 判成数据与复盘。它和正文一样，说的不是这个 skill 在做什么。
#
# 三档都是扫出来的，不是拍的。每一档的取值都取到「再动一格就开始弄坏东西」
# 的前一格：
#
# 低档（body_preview / who_for_zh / repo_description）取 1/4：
#   低=1/2 → 一级翻 25 条    低=1/3 → 34 条
#   低=1/4 → 35 条           低=1/8 → 35 条（与 1/4 逐条完全一致）
#   1/4 是饱和点——再往下压一个数量级，判定一条都不会再变，说明低信噪比字段
#   到这里已经彻底退成「别处全无信号时才起作用」的兜底。
#
# name / dir_name 单独一档（2 倍于其他高信噪比字段）：skill 自己的名字是对
# 「它是什么」最压缩、最没有噪音的一句话。只给它和 description 同权时，
# mcp-builder（名字里就有 mcp）会被 description 里的 typescript/sdk/开发 压成
# 工程开发，executor-mcp、agent-teams 同理。实测：
#   name=1 倍 → mcp-builder / executor-mcp / agent-teams 全判错
#   name=1.5 倍 → 另外 10 条回到自己名字所指的行业（obsidian-bases → 研究、
#                 azure-cost → 工程、newsletter-generation → 内容、safe-refactor
#                 → 工程），逐条核对全是修好
#   name=2 倍 → 上面三条 mcp/agent 类修好，没有新增误判
#   name=3 倍 → 开始弄坏：codex-review（做 code review 的）被名字里的 codex
#               拽去 Agent工具链
# 所以停在 2 倍。
#
# 中间档不再细分。试过把 highlights_zh 从高档降到 1/2：一级多翻 13 条，且这
# 13 条和本轮诊断的稀释问题无关（image-to-code 的「视觉」就在 highlights_zh
# 里，降权直接把它从设计推去 Agent工具链）。没有实测证据支持，就别造这一档。
_W_NAME = 8     # skill 自己的名字/目录名
_W_HIGH = 4     # 这个字段几乎每个词都在说「这个 skill 是什么」
_W_LOW = 1      # 说的不是「这个 skill 在做什么」
SCORE_UNIT = 4  # 分数 ÷ SCORE_UNIT = 等效「高信噪比字段命中数」，喂给置信度公式

# body_preview 是**降权**而不是完全不参与一级判定。实测依据：全量 388 条里
# 只有 9 条（2.3%）的一级判据**只**来自正文，撇开正文就掉进 other。逐条核对
# 这 9 条：2 条是误判（action-converter 靠 "banned-phrase lint" 命中 lint、
# surprise-me 靠正文里的 slide 被判幻灯片），3 条是正确判定（using-superpowers
# / implement-spec / setup-matt-pocock-skills 的 agent、subagent 只出现在正文
# 里），其余中性。一刀切（正文不参与一级）实测一级翻 60 条、12 条掉进 other，
# 会连正确的一起砍掉；降到 1/4 之后这 9 条保留标签但置信度只有 0.39，任何
# 高信噪比字段的信号都能压过它们。who_for_zh 一刀切同样翻 60 条，同理降权。
_FIELD_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("name", _W_NAME),
    ("dir_name", _W_NAME),
    ("description", _W_HIGH),
    ("keywords", _W_HIGH),
    ("skill_path", _W_HIGH),
    ("hg_section", _W_HIGH),
    # i18n 产出的中文字段比英文 SKILL.md 原文干净得多，是最强信号。
    ("one_liner_zh", _W_HIGH),
    ("one_liner_en", _W_HIGH),
    ("highlights_zh", _W_HIGH),
    ("body_preview", _W_LOW),
    # 仓库简介描述的是「整个合集」：同一个 monorepo 拆出的二十条子 skill
    # 共用同一句，和上一轮删掉 full_name 是同一个道理，只能当最弱的兜底。
    # （feed_pack.normalize_item 在 description 缺失时会回填 repo_description，
    # 所以真正只有仓库简介可用的条目不会因为这里降权而失去判据。）
    ("repo_description", _W_LOW),
    ("who_for_zh", _W_LOW),
)

_FM_FIELDS: tuple[str, ...] = ("category", "tags", "scene_l2")


def _weighted_fields(item: dict) -> list[tuple[str, str, int]]:
    """返回 [(字段名, 小写文本, 权重)]，按权重降序，供加权打分用。"""
    out: list[tuple[str, str, int]] = []
    for field, weight in _FIELD_WEIGHTS:
        raw = item.get(field)
        if isinstance(raw, (list, tuple)):
            raw = " ".join(str(x) for x in raw)
        text = str(raw or "").lower()
        if text:
            out.append((field, text, weight))
    fm = item.get("frontmatter") or {}
    for key in _FM_FIELDS:
        text = str(fm.get(key) or "").lower()
        if text:
            out.append((f"fm.{key}", text, _W_HIGH))
    out.sort(key=lambda x: -x[2])
    return out


def _kw_hit(kw: str, fields: list[tuple[str, str, int]]) -> tuple[int, str]:
    """一个关键词的得分 = 命中它的最高权重字段的权重，不是各字段累加。

    取 max 而不是求和：同一个词在 name 和正文里各出现一次，说的仍然是同一件
    事，累加等于奖励复述。fields 已按权重降序，第一个命中就是最高权重字段。
    """
    for field, text, weight in fields:
        if kw in text:
            return weight, field
    return 0, ""


def _score_keywords(
    fields: list[tuple[str, str, int]],
    kws: tuple[str, ...],
) -> tuple[int, list[tuple[int, str]]]:
    """返回 (加权总分, [(权重, 命中词标注)])，命中词按权重降序。"""
    score = 0
    hits: list[tuple[int, str]] = []
    for kw in kws:
        weight, field = _kw_hit(kw.lower(), fields)
        if not weight:
            continue
        score += weight
        # 低权重命中标出出处：下一轮审计要能一眼看出「这条是靠正文撑起来的」。
        hits.append((weight, kw if weight >= _W_HIGH else f"{kw}@{field}"))
    hits.sort(key=lambda x: -x[0])
    return score, hits


# 路径/目录名信号 → 给 design 加权（不是强制覆盖，见 tag_scene 里的说明）。
#
# 这里的词只匹配 skill_path / dir_name / name，**刻意不看 full_name**。
# owner/repo 描述的是「整个合集」而不是「这一个 skill」：一个仓库里几十个
# skill 主题各异，拿仓库名当判据，就是上一轮「skill_path 含 skill 就判
# agent-tooling」的同一个 bug。实测两个反例：
#   Leonxlnx/taste-skill    → 13 条命中 taste，其中 full-output-enforcement
#                             讲的是「禁止 LLM 截断输出」，跟设计毫无关系
#   nexu-io/open-design     → 4 条里 3 条是小红书笔记卡片、推文卡片、聊天
#                             动效浮层，本该归内容创作，却被仓库名拽进设计
# 去掉 full_name 之后 open-design 这个词一条都不再命中，它本来就只是仓库
# 品牌名而非 skill 目录名，一并删掉，免得后人照着这个样子再加一批。
# prototype 也删了：它唯一的覆盖对象是 deploy-prototype（部署原型，实为
# 工程），而 prototype 作为内容关键词已经在 RULES/SCENES_L2 里公平参与打分。
# "-ui" 后缀是 UI 组件库/设计 skill 的命名习惯，实测 4 条命中
# （industrial-brutalist-ui / minimalist-ui / frontend-ui-engineering /
# animal-island-ui）全是设计类，零污染。它接住的正是去掉 full_name 后
# 会掉出 design 的 industrial-brutalist-ui——那条正文里有 "data-heavy
# dashboards"，内容打分反而是 data-review 占先。
_PATH_DESIGN_KEYS = (
    "frontend-design", "web-design", "canvas-design", "brand-guidelines",
    "theme-factory", "figma", "shadcn", "taste", "hallmark",
    "ui-ux", "ui-design", "product-design", "-ui",
)

# 路径信号的权重，单位是「高信噪比字段命中数」（实际加分要乘 SCORE_UNIT）。
# 取 2 而不是「直接 return design」：
#   1 太轻——industrial-brutalist-ui 的正文里有 dashboards，内容打分 data-review=2，
#     design 只有「视觉」1 分，加 1 打平后按字母序会输给 data-review；
#   强制覆盖太重——它让 full-output-enforcement 这类误判还带着 0.86 的高置信度，
#     等于系统对着一个明显错误的结论表现得非常自信。
# 加权之后置信度走统一公式（0.35 + 0.15 × 命中数），纯路径命中只有 0.65，
# 内容信号足够强时（小红书那三条内容打分 3）照样能压过路径。
_PATH_DESIGN_WEIGHT = 2


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

    fields = _weighted_fields(item)
    best_id = ""
    best_score = 0
    best_hits: list[tuple[int, str]] = []
    for cid, _label, kws in SCENES_L2.get(scene_id, []):
        score, hits = _score_keywords(fields, kws)
        if score > best_score:
            best_score = score
            best_id = cid
            best_hits = hits
    if best_score <= 0:
        # 一个关键词都没命中就别硬贴二级：以前默认取第一个子类，
        # 会让 Azure 显示「重构架构」、协方差显示「周报复盘」，等于伪造结论。
        # 返回空，前端不渲染二级徽标。
        return "", 0.0, "no l2 hit"
    conf = min(0.92, 0.4 + 0.15 * best_score / SCORE_UNIT)
    why = ",".join(kw for _w, kw in best_hits[:3])
    return best_id, round(conf, 2), f"l2:{why}"


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

    # 不含 full_name：仓库名描述的是合集不是这一个 skill，见 _PATH_DESIGN_KEYS。
    path_hay = " ".join([
        item.get("skill_path") or "",
        item.get("dir_name") or "",
        item.get("name") or "",
    ]).lower()
    path_kw = next((kw for kw in _PATH_DESIGN_KEYS if kw in path_hay), "")

    fields = _weighted_fields(item)
    scores: dict[str, int] = {sid: 0 for sid, _ in SCENES if sid != "other"}
    hits: dict[str, list[str]] = {sid: [] for sid in scores}

    for sid, kws in RULES:
        score, kw_hits = _score_keywords(fields, kws)
        scores[sid] = score
        hits[sid] = [kw for _w, kw in kw_hits]

    # 路径信号只加权，让内容有机会赢回来；也顺带把「一个规则都没命中」的
    # 纯设计目录（如 skills/brand-guidelines/）从 other 里救出来。
    if path_kw:
        scores["design"] += _PATH_DESIGN_WEIGHT * SCORE_UNIT
        hits["design"].insert(0, f"path:{path_kw}")

    if (item.get("hg_section") or "").strip().lower() == "skills":
        other_hit = any(v > 0 for s, v in scores.items() if s != "agent-tooling")
        if not other_hit:
            scores["agent-tooling"] += SCORE_UNIT
            hits["agent-tooling"].append("hg:Skills")

    best = max(scores.items(), key=lambda x: x[1])
    if best[1] <= 0:
        return "other", 0.2, "no rule hit"
    top = best[1]
    tied = sorted([s for s, v in scores.items() if v == top])
    if len(tied) > 1 and "agent-tooling" in tied:
        tied = [s for s in tied if s != "agent-tooling"] or tied
    sid = tied[0]
    conf = min(0.95, 0.35 + 0.15 * top / SCORE_UNIT)
    why = f"rules:{','.join(hits[sid][:4])}"
    return sid, round(conf, 2), why


def apply_scene(item: dict) -> dict:
    out = dict(item)
    sid, conf, why = tag_scene(out)
    out["scene"] = sid
    out["scene_label"] = SCENE_LABELS.get(sid, sid)
    out["scene_label_en"] = SCENE_LABELS_EN.get(sid, sid)
    out["scene_confidence"] = conf
    out["scene_why"] = why
    l2, l2_conf, l2_why = tag_scene_l2(out, sid)
    out["scene_l2"] = l2
    out["scene_l2_label"] = SCENE_L2_LABELS.get(l2, l2)
    out["scene_l2_label_en"] = SCENE_L2_LABELS_EN.get(l2, l2)
    out["scene_l2_confidence"] = l2_conf
    out["scene_l2_why"] = l2_why
    return out


def scene_chips() -> list[dict]:
    return [
        {"id": sid, "label": label, "label_en": SCENE_LABELS_EN.get(sid, sid)}
        for sid, label in SCENES
    ]


def scene_l2_tree() -> dict[str, list[dict]]:
    """供 Feed 前端：一级 → 二级 chips。"""
    tree: dict[str, list[dict]] = {}
    for parent, children in SCENES_L2.items():
        tree[parent] = [
            {"id": cid, "label": label, "label_en": SCENE_L2_LABELS_EN.get(cid, cid)}
            for cid, label, _ in children
        ]
    return tree
