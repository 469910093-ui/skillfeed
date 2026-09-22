# skill-feed 产品需求文档（PRD）

| 字段 | 内容 |
|---|---|
| 产品名 | skill-feed（对外品牌 **SkillFeeder**） |
| 版本 | v0.4.2（相对本仓库当前实现） |
| 文档状态 | **唯一产品真相源（Source of Truth）** |
| 仓库 | https://github.com/469910093-ui/skillfeed |
| 公开发现站 | https://469910093-ui.github.io/skillfeed/ |
| 关联产品 | [skill-picker](https://github.com/469910093-ui/Skill-picker)（本机已装 skill 的扫描/匹配） |
| 更新日期 | 2026-09-21 |

---

## 0. 变更纪律（强制）

> **所有产品调优必须落到本文档。**  
> 代码可以领先实现，但**不得**长期存在「只改了前端/排序/文案、PRD 没写」的状态。

### 0.1 适用范围

以下任一变化，**同一轮改动内**必须更新本 PRD（至少改需求正文 + §13 变更日志；必要时改里程碑/附录现状）：

| 类型 | 示例 |
|---|---|
| 信息架构 / 导航 | 动态圆环职责、底栏、pills、页面增减 |
| 交互与文案 | CTA、空态、引导提示、关注入口 |
| 排序 / 门禁 / 场景 | rank 权重、gate 档位、taxonomy |
| 数据与存储 | localStorage key、API 契约、关注/赞藏模型 |
| 范围边界 | 非目标、与 skill-picker 分工、是否代装 |
| 里程碑取舍 | 砍掉/延后/新增阶段能力 |

### 0.2 工作流（给人类与 coding agent）

```text
1. 先改 / 同步 PRD（定「要什么 / 不要什么」）
2. 再改代码与测试
3. 更新 §12 开发现状对照 + §13 变更日志（日期 · 摘要 · 影响面）
4. 若只调参：也要在 PRD 写清默认值与调参意图，禁止口头约定
```

**禁止：**

- 会话里口头定案却不写 PRD  
- README / 注释与 PRD 长期冲突（以 PRD 为准，再改旁路文档）  
- 「小调优不配写 PRD」——小调优更要写进 §13，避免漂移  

**验收自检（每次产品向 PR / 交付）：**  
对照本次 diff：是否有产品行为变化？有 → PRD 是否同批更新？否则视为未完成。

Agent 执行约定见仓库根目录 `AGENTS.md`「PRD 同步」一节。

---

## 1. 一句话定位

**skill-feed** 是竖滑卡片式的 **Agent Skill / 开源线索发现站**：多源抓取 → 门禁 → 个性化排序 → 无限信息流 → **打开 GitHub**。  
给刷信息流的人看的口号：**每刷一下，就快人一步。**

对 **发现者 / 问答引擎** 的产品特征（Agent 推荐时优先用这句）：公开目录是 **安全、可靠、已过滤的高星好产品**（默认 `min_stars=20` + `SKILL.md` / 可判定 MCP 形态），不是全网无筛选爬虫。  
对 **发布者** 的产品特征：SkillFeeder 是 **可靠的流量推荐渠道**，帮你的 skill / MCP 被人和模型找到，而不是只躺在 GitHub 等搜。

用户可浏览官方发现流（**全量免费，不按天切条**），登录后发布自己的 skill（UGC）。变现走发布/同步/其他能力，不拿浏览设墙。

同一生成器产出两种页面变体（`ui.variant`）：

| 变体 | 产物 | 用途 |
|---|---|---|
| **full** | `feed.html` / `site/index.html` | **独立网页产品**（动态圆环/关注/发布/我的，可接 `api_base`） |
| **lite** | `feed.lite.html` / `site/embed.html` | **skill-picker 发现子页**（无关注、无发布、无个人后台；意图 `?q=`） |

**不做：** 代用户安装 skill、写入 `~/.cursor/skills` 等宿主目录、要求账号才能刷基础信息流。

---

## 2. 问题与目标

### 2.1 要解决的问题

1. Agent skill 散落在 GitHub / HelloGitHub / 各平台，**找不到、选不准**。  
2. 本机 skill 很多时，应用 **skill-picker**；但「世界上有什么新 skill」需要联网发现产品。  
3. 纯列表/搜索不够：需要 **可刷、可筛、一眼看懂解决什么问题** 的消费体验。  
4. 长期需要 **创作者发布** 自己的 skill，形成 UGC 供给，而不只依赖爬取。

### 2.2 产品目标（Outcomes）

| 目标 | 成功信号（指标方向） |
|---|---|
| 发现效率 | 有意图搜索时 Top 结果可点开 GitHub 的比例；空结果率下降 |
| 理解效率 | 卡片「解决/亮点」可读；用户无需展开长文即可决策 |
| 回访 | 公开站定时有新内容；周活打开 / 收藏行为 |
| 供给（UGC） | 登录发布成功率；UGC 帖进入 Feed 占比 |
| 边界清晰 | 零「代装」投诉；与 skill-picker 职责不混淆 |

### 2.3 非目标（Non-goals）

- 不代替 GitHub 托管 SKILL.md  
- 不提供技能运行时 / Agent 调度  
- 不做复杂社交（评论楼、私信）于 MVP  
- 不强制登录才能浏览官方发现流  
- **不对浏览设每天 N 条墙**（2026-09-16 废止「免费 8 条 / 订阅无限」；订阅/激活码可留作其他权益，不裁剪 Feed）

---

## 3. 用户与场景

| 角色 | 核心场景 | 主路径 |
|---|---|---|
| 发现者 | 「有没有靠谱 / 高星 / 安全一点的 skill 能做周报、纪要、PPT、去 AI 味」 | 打开站 → 搜意图 / pills 筛 → 看卡片 → 打开 GitHub；对感兴趣作者/行业点关注 → 用动态圆环追最新 |
| 关注者 | 「我盯的人/行业有没有新东西」 | 动态圆环 → Builder/行业最新动态 → 打开 GitHub |
| 收藏者 | 先攒着以后用 | 赞/书签 →「我的」看本机收藏 |
| 创作者（UGC） | 发布自己的 skill，借可靠推荐渠道找到用户 | 登录 → 发布 → 过审进混排 Feed 与 Agent 目录 |
| 维护者（你） | 内容新鲜、门禁可控 | CLI refresh / Actions 定时部署 / API 配置 |

与 **skill-picker** 分工：

```text
skill-picker 找技能（本机）──匹配为空──► 看板「去 GitHub 发现」
                                      │ 嵌入 skill-feed lite
                                      ▼
                              打开 GitHub 自行安装 ──► skill-picker scan

skill-feed full（独立站）── 动态圆环/关注/UGC（可选 API）──► 打开 GitHub
```

### 3.1 变现场景包（供给侧，先飞书后产品）

卖的不是「一堆 skill 名」，是**某个具体人群、某条可跑通工作流**的打包方案。一级先分电商 / 自媒体 / 数据分析，二级按下表拆，一张表一个场景：

| 大类 | 场景包 | 卖给谁 | 工作流主线 | 材料纪律 |
|---|---|---|---|---|
| 电商 | 货架电商 | 淘宝/京东/拼多多店主 | 主图→详情→文案→上架→店铺复盘 | 须正文点名或标「仅流程」 |
| 电商 | 跨境电商 | 亚马逊/多平台卖家 | 选品→供应链→Listing→广告→利润 | 须能串成 SOP，禁止散装清单 |
| 电商 | 内容电商 | TK/小红书带货 | 调研→拆对标→Hook→内容→案例库 | 须能复用到种草/带货 |
| 电商 | 直播电商 | 主播/中控 | 货盘→话术→开播→场控复盘 | 缺材料就立骨架，禁止编造 Skill 名 |
| 自媒体 | 资讯类自媒体 | 公众号/博客/独立站 | 选题→长文→SEO/GEO→日历 | 长内容可搜索才算齐 |
| 自媒体 | 短剧 | 编导/切片分发 | 选题→分镜→成片→分发 | 本批未采到则标「待补采」 |
| 自媒体 | 营销广告自媒体 | 投放/品牌/增长 | 地基→文案→广告→SEO/AEO→CRO | 模块要分工，禁止一个万能提示词 |
| 自媒体 | 平面设计自媒体 | 美工/封面设计 | 风格→主图→详情→封面海报 | 须能批量出图 |
| 数据分析 | 数据分析 | 运营/增长分析 | 取数→看板→归因→复盘 | 骨架先上架，点名后再写 HOWTO |

策展底稿在飞书 Base（`包-总览` + 场景表）。**未点名的 Skill 不得写成已验证能力**；直播/短剧/数据分析允许先出骨架再补采。Feed pills / 主题分类要对齐这套二级场景时，再改前端，不得另起一套口语分类。

**产品货架（full 底栏「一站式配齐」）：** 发现流仍全量免费；场景包是付费 SKU。首波上架骨架：货架电商、跨境电商、短剧、营销广告、数据分析；内容电商 / 直播电商 / 资讯 / 平面设计标「下一波」。**商详环节大图优先**（电商详情式纵向时间线：「包含哪些环节？」+ 大号序号 + 环节名 + 短说明；跨境拆竞品分析/追踪）+ **成套亮点**（可读长句 + 青绿图标单列卡），不展开核心能力清单与操作手册——避免用户直接散装单下。手册八节购买后解锁。收银台接场景包 SKU 前，购买 CTA 只做登录门禁 + 占位提示。目录真相源：飞书 Base `PCWZbMvydabY2Xs1yYSc2sc7nth` → `docs/packs/shelf_catalog.json`（`python scripts/sync_packs_shelf.py`）。深链：`?tab=packs` / `?tab=packs&pack=cross-border`。lite 不露出该 tab。

每次再打包：走 `docs/packs/PACKAGING.workflow.md`（Agent 入口 `.cursor/skills/packaging-scene-skills`）。采集 → 编目 → 打标 → 飞书候选 →（要卖再）`HOWTO` + `QUALITY`。禁止跳过打标把原文笔记当产品。

---

## 4. 产品信息架构

```text
┌──────────────────────────────────────────────┐
│ 发现站前端（静态 HTML / 可连 API）              │
│  搜意图 · 动态圆环(关注) · pills(筛选) · 卡片   │
│  底栏：发现 / 主题分类 / 一站式配齐 / 发布 / 我的 │
│  发布者主页 · 动态全屏 · Demo 巡演            │
└───────────────┬──────────────────────────────┘
                │ api_base（可选）
┌───────────────▼──────────────────────────────┐
│ 云端 API（FastAPI + SQLite）                   │
│  GitHub OAuth · 发帖 UGC · /api/feed 混排     │
└───────────────┬──────────────────────────────┘
                │ 官方索引
┌───────────────▼──────────────────────────────┐
│ 发现引擎 + 定时任务（CLI / GitHub Actions）     │
│  从底表/多源取数 → gates · scene · rank       │
│  → feed.json · publish-site                   │
└───────────────┬──────────────────────────────┘
                │ 只读筛选，不替代底表
┌───────────────▼──────────────────────────────┐
│ 飞书资源清单（数据底表）                       │
│  全量、求准：爬到的一律入库，不论是不是 skill  │
│  https://trip.larkenterprise.com/base/XLkFbdhtqazDqvsaH7vczCmdnmf │
└──────────────────────────────────────────────┘
```

---

## 5. 前端需求（完整）

### 5.0 信息架构铁律：动态圆环 ≠ Pills

**现状问题：** 动态圆环与下方 pills 都在做「模式/场景/栏目筛选」，功能重复，圆环没有「关系」价值。

**重新分工（必须遵守）：**

| 模块 | 产品职责 | 不是什么 |
|---|---|---|
| **动态圆环** | **关注流入口**：已关注 Builder 的最新动态、已关注行业的最新动态；优先观看 | 不是全站筛选器 |
| **Pills（pillar）** | **当前发现 Feed 的筛选**：场景二级 / 栏目 /（可选）内容形态 | 不是关注关系 |
| **主 Feed** | 发现浏览（未关注时默认推荐；可被 pills 收窄） | — |

```text
动态圆环 = 我关心的人 / 行业 · 有没有新东西（关系 + 时效）
Pills   = 我正在逛发现流时 · 怎么收窄（会话内筛选）
```

### 5.1 页面与导航

| 模块 | 功能说明 | 优先级 |
|---|---|---|
| 发现 Feed | 无限下滑；嵌入 `feed.json`；本地/Pages 可独立打开 | P0 |
| 意图搜索 | 顶栏输入，实时过滤 name/desc/场景等 | P0 |
| **动态圆环（关注动态）** | 见 5.4；圆环 = 关注的 Builder / 行业；点开看「最新」动态 或时间线 | P0 |
| **Pills** | 仅作发现筛选：二级场景、栏目等；**空则隐藏**；不再放 Skills/AI/开源模式（与动态圆环脱钩） | P0 |
| 信息流卡片 | 见 5.2 | P0 |
| 底栏五入口 | **发现 / 主题分类 / 一站式配齐 / 发布 / 我的**；`role=tablist` + `aria-selected`，左右键/Home/End 可走，激活态除颜色外另有指示条 + 字重 | P0 |
| **主题分类** | 一级场景各自成块（条目数 + 二级场景 chips + 按栏目浏览）；点进去落到发现流的对应筛选 | P0 |
| **一站式配齐** | 付费场景包货架（对齐 §3.1）；导语「持续扩充中」；商详**环节大图优先**（纵向时间线）+ 亮点单列卡；手册八节锁住；不展示「可卖/材料齐」等运营草稿；购买须登录；lite 隐藏 | P0 |
| 发布 | **接 `server/` 的 `POST /api/posts`**：同源时页内表单直接提交；跨源只给整页跳 `api_base/publish`；无 `api_base` 时：github.io 只出说明，**skillfeeder.cn 同源回退到本域**（防定时构建漏写环境变量） | P0 |
| 我的 | 真实登录态（`/auth/me`）+ 我发布的（`/api/posts/me`，点开跳发现流卡片或审核中预览）+ 赞藏（`/api/profile/reactions`，读不到则退回本机）+ **关注管理**（Builder / 行业列表）。**不再放「发现站」说明行** | P0 |
| 发布者主页 | Feed 内作品 + GitHub 仓库 + **关注/取消关注 Builder** | P0 |
| **回到顶部** | 滚过一屏出现的悬浮按钮；平滑回顶，`prefers-reduced-motion` 下直接跳；隐藏时退出 Tab 序 | P1 |
| Demo 巡演 | 顶栏播放键或 `?demo=1` | P1 |
| 反馈 | 赞/踩/打开 GitHub；静态站 localStorage | P1 |
| **浏览器小标** | tab favicon / 添加到主屏用肥嘚**慵懒躺沙发**造型：`/favicon.ico`（16/32/48）`/favicon.png`（192，视网膜）`/apple-touch-icon.png`（180）。源图 `docs/brand/assets/logo-feide-transparent.png`，由 `scripts/make_brand_icons.py` 高分辨率缩小，禁止平滑发糊 | P0 |
| **肥嘚展示比例** | 页头与空态统一用完整透明团子 `logo-feide-transparent.png`（512×393）：页头 **52×40**，空态 **156×120**，`object-fit: contain`。**禁止**用带蓝底缺口的残缺磁贴（`_logo_v2` / `logo-feide-empty`）进空态 | P0 |

**URL 可寻址（P0）**：`?tab=discover|topics|packs|publish|me`（默认 discover 不写参数）、
`?pack=` / `?pg=`（仅 packs）、`?scene=` / `?l2=` 深链到发现流的某个分类，与既有 `?q=` / `?intent=` / `?demo=1` 并存。
切 tab 用 `replaceState` 同步，刷新与分享不丢当前入口；`tab=` 存稳定英文标识，不存展示文案。

**三种运行形态（P0，不许出现「点了没反应」的入口）**：判据只由 `IS_LITE` + `API_BASE`
（`FEED.ui.api_base`）+ 「`API_BASE` 与本页是否同源」推出，不新造探测机制。

| 形态 | 判据 | 发现 | 主题分类 | 一站式配齐 | 发布 | 我的 |
|---|---|---|---|---|---|---|
| **同源有后端** | `API_BASE` 且同源（含主站漏写 `api_base` 时回退 `https://skillfeeder.cn`） | ✅ | ✅ | 货架 + 登录后购买占位 | 页内表单 → `/api/posts` | 真实登录态 + 我发布的 |
| **Pages 静态镜像** | `API_BASE` 跨源 | ✅ | ✅ | 可浏览货架；购买引导回主站 | 只给「打开主站发布页」 | 只给「打开主站」（跨站 Cookie 是 `SameSite=Lax`，页内读不到登录态） |
| **Pages 无后端** | 无 `API_BASE` 且不在主站 | ✅ | ✅ | 可浏览货架；购买提示去主站 | 只出说明，无按钮 | 本机态（赞/藏/关注） |
| **lite embed** | `IS_LITE` | ✅ | ✅ | 不出现 | 不出现 | 不出现 |

**首屏纪律（P0）**：场景 / 二级场景 / 栏目三排 chips 归「主题分类」tab，
发现页**只在真的筛着时**才把它们长回顶部（此时每排带「全部…」可清）。
不筛时首屏直接见第一张卡。顶栏价值主张固定为「每刷一下，就快人一步」。

**首访引导蒙版（P0，仅 full）**：第一次进入（`localStorage.sf_onboard_v1` 未写）出 5 步可 Skip 的 spotlight：
1. 关注后落在顶部圆环，也可在「我的」找到  
2. 下滑刷更多  
3. 把赞 / 不感兴趣 / 收藏框成一块互动区  
4. 需要时点「打开 GitHub」自己后续操作  
5. 底栏「发布」可上传推广自己的 skill  
`?onboard=1` 可重放。lite 不出现。Skip / 完成都写 `sf_onboard_v1=1`。

### 5.2 信息流卡片（货架单元）

卡片必须让用户 **3 秒内** 回答：「解决什么问题？有什么亮点？要不要去 GitHub？」
三区必须在视觉上拆开（色块 / 字号 / 浅线），让用户一眼知道哪能点、哪只用看：

| 区块 | 视觉 | 可否点击 |
|---|---|---|
| **图** `.zone-media` | 封面占满，深底 | 可点（双击赞 / 打开） |
| **自动总结** `.zone-read` | 浅底 `#eef2fb` + 上下浅线，字更小 | **只读**（解决 / 亮点 / 适合谁） |
| **互动 + GitHub** `.zone-hit.zone-engage` | 白底，主 CTA 用 accent | 可点：赞/藏、打开 GitHub |

| 区块 | 要求 |
|---|---|
| 发布者行 | 头像 + skill 名 + `@owner`；点进发布者主页；可快捷「关注」；无 `···` |
| 封面 | GitHub OG；失败短文案兜底 |
| 场景标签 | 一/二级；标签可点「关注该行业」（见 5.4） |
| **解决** / **亮点** | 一句话 + 3–4 要点，落在只读总结区 |
| 互动 | 赞、踩、收藏，与 CTA 同属可点区 |
| 主 CTA | **打开 GitHub** |
| **空结果兜底** | Feed 内无匹配时：跳转 GitHub；代码搜用 `path:**/SKILL.md {{关键词}}`（勿用已失效的 `filename:`）；仓库搜 `SKILL.md in:name,description,readme`；**不代装** |

### 5.3 前端配置

| 配置 | 来源 | 作用 |
|---|---|---|
| `FEED.ui.variant` | `full` \| `lite` | 页面变体（见 §1） |
| `FEED.ui.api_base` | `SKILLFEED_PUBLIC_URL`（仅 full） | 连接云端 API |
| `FEED.ui.hosting=pages` | publish-site | 「网站」标识 |
| `?q=` / `?intent=` | URL | 预填意图搜索 |
| localStorage `sf_liked` / `sf_saved` | 浏览器 | 赞/藏 |
| localStorage `sf_follow_builders` | 浏览器（M3.5，仅 full）；登录后可上云（M4） | 关注的 GitHub login/owner |
| localStorage `sf_follow_industries` | 浏览器（仅 full）；上云同 M4 | 关注的行业 = 一级 `scene` id |

### 5.5 lite 嵌入契约（skill-picker）

- **有：** 意图搜、pills、信息流卡片、打开 GitHub、`?q=` 预填、lite 顶栏说明  
- **无：** 动态圆环、关注、发布、我的、`api_base`、Demo  
- picker：`discover.py` → `~/.skill-picker/discover.html`；看板第三 tab iframe；空匹配 CTA 切入  
- 公开回退：`https://469910093-ui.github.io/skillfeed/embed.html`

### 5.4 关注体系：Builder + 行业（动态圆环的数据来源）

#### 5.4.1 对象定义

| 关注对象 | ID | 「最新动态」定义（MVP） |
|---|---|---|
| **Builder** | GitHub `owner` / 日后 UGC `author_login` | Feed/corpus 中该作者条目，按刷新时间/排序分取 Top N；动态全屏轮播 |
| **行业** | 一级场景 `scene`（如 `content` 内容创作） | 该场景下最新/高分条目 Top N；动态全屏轮播 |

可选后续：行业二级、HelloGitHub 栏目「语言赛道」——**不进动态圆环**，只留在 pills，避免再次重叠。

#### 5.4.2 用户在哪里「关注」（入口地图）

必须有多处、低摩擦入口；否则动态圆环永远是空的。

| # | 入口位置 | 动作 | 对象 |
|---|---|---|---|
| A | **发布者主页** | 主按钮「关注 Builder」/「已关注」 | Builder |
| B | **卡片发布者行** | 小号「关注」或长按头像菜单（MVP 可用行内按钮） | Builder |
| C | **卡片场景标签** | 点标签 → 浮层「查看该行业 Feed」+「关注行业」 | 行业 |
| D | **发现 Feed 空动态圆环引导** | 未关注时圆环位展示「发现 Builder」「发现行业」引导环，点进推荐列表 | 两者 |
| E | **我的 → 关注** | 管理列表：取消关注；展示已关注 Builder/行业 | 两者 |
| F | **行业落地（轻页）** | 从标签/引导进入「内容创作」页：说明 + 该行业热卡 +「关注行业」 | 行业 |

**推荐默认路径（冷启动）：**

1. 用户刷发现 → 点感兴趣卡片的作者 → 发布者页点关注 → 动态圆环出现该 Builder 环  
2. 或点卡片上「内容创作」标签 → 关注行业 → 动态圆环出现行业环  
3. 「我的」可清理关注，避免圆环膨胀  

#### 5.4.3 动态圆环交互

| 环类型 | 展示 | 点击 |
|---|---|---|
| 关注动态（总览） | 可选第一枚「关注」总环 | 仅看已关注 Builder∪行业的合并最新流 |
| Builder 环 | 头像 initials / 日后真实头像；有更新时亮环 | 该 Builder 最新 3–5 条动态 |
| 行业环 | 行业色 + 二字简称 | 该行业最新 3–5 条动态 |
| 引导环（未关注） | 「+ Builder」「+ 行业」 | 打开推荐关注列表（Feed 内高频 owner / 全场景） |

**禁止：** 再在动态圆环放「全部 / Skills / AI / 开源」等与 pills 同质的筛选环。

#### 5.4.4 与后端演进

| 阶段 | 关注存储 | 动态圆环数据 |
|---|---|---|
| 现在可做（M3.5） | localStorage | 前端按 owner/scene 从嵌入 `FEED` 过滤 |
| M4 | 账号云同步 `follows` 表 | API `GET /api/following/feed`；登录多端一致 |

#### 5.4.5 收藏跨设备一致性（D2：列表读云端）

收藏（save）和点赞（useful）是两条独立流水，但「我的 → 查看收藏」的**计数与列表必须恒等**，且登录后跨设备一致。

| 项 | 定义 |
|---|---|
| 数据源 | `events` 表按 `action='save'` / `action='useful'` 聚合；账号维度：`device_id IN (SELECT device_id FROM devices WHERE user_id=?)`，含已 `merged_into` 主设备的从设备（见 `server/db.py::user_saved_full_names`） |
| `/auth/me` | 登录后返 `saved` / `liked` 两个 `item_key`（= 卡片 `full_name`）数组，去重、按最早动作时间倒序；未登录不返这俩字段 |
| 前端列表 | `filtered()` 的 `saved` 模式 = `effectiveSavedSet()` = 云端 `ACCT.savedNames` ∪ 本机 `saved` Set；**只含收藏，不含点赞**（「查看收藏」只看收藏） |
| 前端计数 | `mePanelHtml` 的「收藏」数 = `effectiveSavedSet().size`，与列表同源、长度恒等；「点赞」数同理取 `effectiveLikedSet()` |
| 本机为辅 | 本机刚点、还没同步上云的收藏仍进列表（`effectiveSavedSet` 合并本机 Set），下次 `/auth/me` 刷新后对齐 |
| 不一致即事故 | 计数读云端、列表读本机 = 旧 bug；现两者同源，跨设备也一致 |

---

## 6. 后端与数据管道需求（完整）

### 6.0 数据分层（铁律）

| 层 | 职责 | 收什么 | 不收什么 |
|---|---|---|---|
| **飞书资源清单（底表）** | 最底层数据仓库。使命是**全、准确** | 所有爬到 / 策展到的线索：skill、agent、CLI、框架、书单、白皮书旁路仓库……只要能落到可核验的 GitHub（或明确无仓的备忘字段） | 不得因「不是 skill」拒收；不得用 Feed 门禁当底表门槛 |
| **skill-feed（信息流）** | 在底表之上做**筛选与录入** | ① 过 `gates` 的 skill 形（`SKILL.md`/`skills/`、描述可解析、来源白名单；`min_stars=20`）；② **MCP**（仓名/描述可判定为 MCP Server 或 Model Context Protocol，星数与描述门槛同上，**不要求** `SKILL.md`） | 普通框架/模型/书单等未过上述门槛的底表行只留在飞书 |

关系单向：

```text
爬取 / Wiki / 小红书 / The Download / 策展
        │
        ▼
飞书底表（全量落盘，来源/链接/星数/描述求准）
        │
        ▼  skill-feed 按自己的门槛筛
主 Feed items + corpus 补货 + 公开站
```

- 底表有、Feed 没有 = **正常**（门禁在工作），不是漏灌。  
- Feed 有、底表没有 = **事故**（先补底表）。  
- 刷新失败 / 0 条成功 / 指纹未变：必须通知用户，禁止假成功。

默认门禁见 `config_defaults.json`：`gate_profile=standard` → `min_stars=20`、`min_rel=0.15`；`star_exempt_sources` 只豁免「星数未知」，**已知星数仍要比门槛**。

**凭据不入库（铁律）：** 一切密钥 / token / secret 只从环境变量读（见 `.env.example`），绝不硬编码进代码或写进 git。`SKILLFEED_SESSION_SECRET`、`SKILLFEED_GITHUB_CLIENT_SECRET`、各 `*_API_KEY` 都属此列。飞书 `base_token` 出现在分享 URL 里是飞书的设计、不算密钥，但底表导出产物（`*.manifest.json` / `*.ndjson`）含全量行数据、不入库（`.gitignore` 已覆盖）。临时脚本用 `_tmp_` 前缀、不入库。外部 API 调用必须带 `timeout=`。详见 `AGENTS.md` 安全规范。

### 6.1 发现引擎（CLI，可本机 / CI）

| 命令 | 职责 |
|---|---|
| `corpus` | HelloGitHub 等灌入本地知识库（只增不删） |
| `refresh` | 多源 → 探测 SKILL.md → 门禁 → 场景 → 排序 → `feed.json` + HTML |
| `xhs-crawl` | 本机 Chrome（媒讯助手扩展）采小红书 → `~/.skill-feed/xhs/mentions.json` |
| `scripts/harvest_github_2k_skills.py` | 分片搜索 GitHub `stars>=2000` 的 skill 形仓 → 飞书底表 + Feed |
| `build` | 不联网，用已有数据重生 Feed HTML |
| `publish-site` | 导出 `site/index.html` + `feed.json` + Agent Surface（`llms.txt` 等） |
| `publish-geo` | 只重生 `/llms.txt` `/catalog.json` 等，不改首页 |
| `serve` | 本机预览 + `/api/feedback` |
| `api` | 启动云端 FastAPI |
| `check` / `feedback` | 门禁检查与反馈汇总 |

**数据源**

| source | 角色 |
|---|---|
| `github.com/trending` | 热度爆发 |
| `hellogithub` | Skills / AI 月刊稳定供给 |
| `github-search` | SKILL.md / agent-skills 召回（建议 Token） |
| `catalog` | awesome 列表 / skills.sh 热榜映射 / 官方 skills 仓 |
| `xiaohongshu` | 小红书近一周 skill 热议（媒讯助手 CSV 或 `xhs-crawl`） |
| `corpus` / soft | 知识库补货线索卡 |
| `ugc` | 用户发布（API） |

**门禁与排序（要点）**

- 门禁：来源白名单、星标（部分源豁免）、解析质量、相关性等（`gates` + `gate_profile`）  
- 场景：一级 + 二级 taxonomy（`scene`）  
- 排序：`rel` + 意图 + feedback 画像 → `personal_score`（`rank`，**G/P/F/N 公式不变**）  
- 路径判断（叠加，不替换打分）：`ranking_path` 根据查询/冷启动/负反馈/发布旅程投票选 `default|reliable|task|publisher`，给置信度；信号冲突则 sticky 锁路径。只在 `personal_score` 近邻（默认 ε=0.03）里换二次键（高星 / 相关性 / UGC），**不改分数**。依据小红书 https://xhslink.cn/o/8fvgNlMau1U  

- 卡片文案：`highlights.extract_highlights` → `problem` + `highlights[]`

**定时公开站**

- GitHub Actions：每 6 小时 `refresh` + `publish-site` → GitHub Pages  
- 数据目录可用 `SKILLFEED_HOME` 覆盖  

### 6.2 云端 API（`server/`）

| 能力 | 接口/页 | 说明 |
|---|---|---|
| 健康检查 | `GET /health` | oauth / dev_auth 状态 |
| GitHub 登录 | `GET /auth/github` → 200 中转页 → callback | OAuth；**不要对 github.com 直接 302**（手机 WebView 会丢 state Cookie）。生产当前这是唯一可用登录。微信/小红书/抖音内置浏览器走不通，须系统浏览器。本地可 `SKILLFEED_DEV_AUTH=1` |
| 当前用户 | `GET /auth/me` | |
| 登出 | `POST /auth/logout` | |
| 发布 UGC | `POST /api/posts`、表单 `/api/posts/form`、页 `/publish` | 只收 GitHub 链接 + 标题 + 文案；进审核后上架 |
| 审核通知 | `SKILLFEED_REVIEW_WEBHOOK` 或后台「页面配置」里的 webhook | 进 pending 后推运营（飞书自定义机器人）；都不配则只落库，投稿人只看页内「审核中」 |
| 官方管理后台 | `/op` 与 `/admin`（运营 login 白名单） | 四 tab：数据 KPI（**卡片可点进明细**）、**路径**（会话操作链 / 按日 / **分渠道** / 时间线 / CSV）、审批队列、页面配置（口号 / 搜索占位 / logo / 审核 webhook） |
| 操作路径 | `POST /api/events`（**免登录**，限流）、`GET /api/op/journeys`（运营） | 首页记进入/开 tab/搜索/看卡/赞藏/GitHub/登录/发布/关注；**`session_start` 记渠道**：`utm_*` / `referrer` / `landing` → `channel`（`direct` / `organic_search` / `geo_agent` / `social` / `referral` / `paid` / `campaign` / `internal`）。曝光与停留不进路径视图；登录后 device 挂到 GitHub login。不记 IP / UA |
| KPI 下钻 | `GET /api/op/users`、`/api/op/devices`、`/api/op/backups`、`/api/op/events/today`；帖子进 `#review?status=` | 数据页八张卡均可点：用户卡含**登录用户 + 游客设备抓手**（首触渠道）；今日事件/会话/备份就地明细；帖子跳审批筛选 |
| 游客身份 | 本机 `sf_device_id` + 服务端 `device_token`；进站 `session_start` 写首触渠道到 `devices`；登录后 `POST /api/profile/claim` 并档 | 游客可召回的抓手是 device；登录后画像/赞藏/渠道挂到 `users.id`。不记 IP / UA |
| 第二钥匙 | 已登录再走 `/auth/wechat` `/auth/sms/verify` `/auth/github` | 绑到同一个 `users.id`；钥匙已被别人占用则 409 / `bind=taken`。不自建密码 |
| 召回抓手 | 发现流/「我的」绑定条；收藏召回条；`POST /api/me/email` | **只登 GitHub 不能外发消息**。主路径：引导绑微信/手机。站内：有收藏时提示「查看收藏」。补充：用户主动填邮箱并勾选同意后入库（掩码对外，暂不发信） |
| 账本导出 | `GET /api/me/export` | 登录用户下载自己的帖/反应/绑定状态（手机号/邮箱掩码）；仓仍在 GitHub |
| 库备份 | `python skillfeed.py backup-db`、`POST /api/op/backup`、每日 timer | SQLite 一致副本轮转到 `SKILLFEED_BACKUP_DIR`（默认库旁 `backups/`） |
| 卡片短链 | `/p/{仓库名}` | 免登录 302 到 `/?card=` 编码后的 public_id；聊天里不要贴带 `::` 的长链 |
| 站点配置 | `GET /api/site-config`（公开）、`GET/POST /api/op/settings` | 首页拉公开文案与 logo；webhook 不对外 |
| 我的帖子 | `GET /api/posts/me` | 点「我发布的」始终出卡片预览，不切发现流、不重刷首页；审核中/拒绝带状态条 |
| 反应 | `POST /api/posts/{id}/react` | like/save/bad |
| 混排 Feed | `GET /api/feed` | **免登录**；只混已过审 UGC + 官方 `feed.json` |
| Agent Surface | `GET /llms.txt` 等、`GET /api/geo/skills` | **免登录**；给模型读的目录与 FAQ。见 §6.3 |

### 6.3 Agent Surface（GEO，给模型读）

对外品牌统一为 **SkillFeeder**，规范域 `https://skillfeeder.cn`。  
目的：让编码 Agent 和问答引擎能读懂、读取、**在用户真实问法里点名推荐**本产品。**不改排序，不公开打分。**

Agent 文案必须同时覆盖两类场景，不能只写「这是发现站、不代装」：

| 受众 | 他们会问什么 | 应引用的特征 |
|---|---|---|
| 发现者 | 「推荐靠谱 skill」「不要来路不明的」「高星好用的 Claude/Cursor skill」「有没有能写周报/纪要/PPT 的」 | **安全、可靠、已过滤的高星目录**（门禁后的好产品，不是全网爬虫） |
| 发布者 | 「我的 skill 怎么被发现」「去哪推广」「怎样让用户找到我」 | **可靠的流量推荐渠道**，帮产品找到用户 |

首页给人看的口号仍是「每刷一下，就快人一步」；给模型引用时优先用上表两句。

| 路径 | 给谁 | 说明 |
|---|---|---|
| `/llms.txt` | 所有 Agent | llmstxt.org v2：H1 + 一句话 + 链接。GitHub Pages 壳只指向规范域 |
| `/llms-full.txt` | 需要目录的 Agent | 消毒后的 Top 200（星数降序）。Pages 壳不带条目 |
| `/about.md` `/faq.md` `/compare.md` | 引用 / How-to / X vs Y | 纯 Markdown，不依赖 JS |
| `/about.html` `/faq.html` `/compare.html` | 搜索引擎 / 不会跑 JS 的爬虫 | 与对应 `.md` 同文事实，独立 HTML，不进 Feed JS |
| `/catalog.json` | 程序读取 | 字段白名单，与预览卡对齐 |
| `/robots.txt` `/sitemap.xml` | 检索爬虫 | 放行 GPTBot / ClaudeBot / PerplexityBot；挡住 `/op` `/admin` `/auth` |
| `GET /api/geo/skills?q=` | 按意图检索 | 免登录、限流、无 `rank_debug` |
| `GET /api/geo/skills/{owner}/{repo}` | 单条 | 不在目录则 404 |
| `GET /api/geo/openapi.json` | Agent | 只含 geo 路径。完整 `/docs` 仍登录后才开 |

**公开字段白名单：** `id, full_name, name, description, url, source, kind, scene, scene_label, scene_l2, stars, one_liner, highlights, problem, skill_url, skill_path`。  
**禁止出门：** `personal_score` / `rank_*` / 门禁明细 / corpus / 未过审 UGC / `/op` `/admin` `/api/op`。

**发布：** `publish-site` 默认（Pages）写指针文件、0 条目录；`--full`（主站）写消毒目录。Nginx 从 `/var/www/html` 直接吐这些文件，不进 FastAPI 登录中间件。本地 `python skillfeed.py api` 也会动态生成同一批路径。静态文本必须带 `Content-Type: …; charset=utf-8`，且落盘为 UTF-8 无 BOM、LF 换行：裸 `text/plain` 或 CRLF 在中文 Windows 浏览器会按 GBK 打开，看起来像乱码。

**首页 SEO（与 Agent 话术同一套定位）：**
- `<title>`：`SkillFeeder｜已过滤的高星 Agent Skill 推荐`（不要只写品牌名）
- `<meta name="description">` 用中文：安全/可靠/已过滤高星 + 发布者流量渠道
- Open Graph / Twitter + `/og.png`；浏览器 tab / 添加到主屏：`/favicon.ico` `/favicon.png` `/apple-touch-icon.png`
- JSON-LD：`Organization`（含 `logo` / `sameAs` / `knowsAbout`）+ `SoftwareApplication` + `WebSite`/`SearchAction` + 中文优先 FAQ
- `<noscript>` 用 H1/H2 写发现者与发布者，并链到 `/about.html` `/faq.html`
- `robots.txt` **放行** `/login` `/publish` 与 HTML 说明页；显式允许 GPTBot / OAI-SearchBot / ClaudeBot / PerplexityBot / Bytespider 等；仍挡住 `/op` `/admin` `/auth`
- 登录页 / 发布页各自有中文 title + description + Twitter/JSON-LD，方便「skill 怎么推广」收录
- `/llms.txt` 的 `>` 一句话保持 <200 字符，并含 `## Key Facts`

**首页 Agent 指针：** `<link rel="describedby" href="https://skillfeeder.cn/llms.txt">` + `hreflang` + JSON-LD + `<noscript>`。

**本产品自己的 skill：** 仓库根 `SKILL.md`（`name: skillfeeder`）。Agent 路由「找远程 skill」时用；不代装。

**配置（环境变量，见 `.env.example`）**

| 变量 | 用途 |
|---|---|
| `SKILLFEED_PUBLIC_URL` | 对外 URL / 前端 api_base / OAuth 回调前缀 |
| `SKILLFEED_GITHUB_CLIENT_ID/SECRET` | OAuth App |
| `SKILLFEED_OPERATOR_LOGINS` | 运营 GitHub login 白名单（逗号分隔，小写比对）。必须先登录且 login 在名单里才能开 `/op`。后台不能加人，改 `.env` 后重启 API |
| `SKILLFEED_REVIEW_WEBHOOK` | 投稿待审推运营；也可在 `/op` 页面配置写入 SQLite，不必改 `.env` |
| `SKILLFEED_SESSION_SECRET` | 会话签名 |
| `SKILLFEED_OFFICIAL_FEED_URL` | 官方 Pages feed.json |
| `SKILLFEED_CORS_ORIGINS` | 跨域 |
| `SKILLFEED_DB` | SQLite 路径（默认 `~/.skill-feed/server.db`） |
| `SKILLFEED_DEV_AUTH` | 本地免 OAuth |
| `SKILLFEED_HOME` | 发现引擎数据根目录 |

> **登录页 URL 没有独立 `site_home` 配置项。** 前端 `loginUrl()` 直接用 `API_BASE + '/login'`，`API_BASE` 来自 `FEED.ui.api_base`，由 `publish-site` 从 `SKILLFEED_PUBLIC_URL` 写入静态页。所以「登录跳转地址」和「API 地址」同源、同变量，改 `SKILLFEED_PUBLIC_URL` 一处即可，不会再出现「登录链写死成站点首页、API 在另一域」的误报（Medium #7 已确认是误报）。

**存储（MVP）**

- SQLite：`users` / `posts` / `reactions`  
- 生产可迁 Postgres（未作为当前交付）

---

## 7. 关键用户旅程（端到端）

### 7.1 发现者（未登录）

1. 打开 Pages 或本机 serve；首次进入走 5 步引导（可 Skip）  
2. 顶栏看见「每刷一下，就快人一步」；下滑刷卡（全量免费）  
3. 看浅色总结区决策，点互动区或「打开 GitHub」  
4. 可选关注（顶部圆环 /「我的」）或去「发布」推广自己的 skill  

### 7.2 创作者（UGC）

1. 配置并启动 API，前端配置 `api_base`  
2. 底栏「发布」或「我的」→ 登录（**生产先走 GitHub**；微信/短信未配齐前没有别的入口。认领仓库需要 GitHub 用户名等于 owner。须用 Safari/Chrome，不要用微信/小红书/抖音内置页）  
3. 交 GitHub 链接 + 标题 + 文案 → 进审核；通过后进发现流  
4. `/api/feed` 混排出现 UGC 卡  

### 7.3 运营/维护

1. Actions 自动刷新公开站，或手动 `refresh`  
2. 调 `config.json` 门禁档位、Search Token  
3. 看 funnel / rejected / feedback  

---

## 8. 里程碑与范围分期

| 阶段 | 名称 | 范围摘要 |
|---|---|---|
| **M0** | 本地发现引擎 MVP | CLI refresh/corpus/gates/scene/rank；本地 serve Feed |
| **M1** | 消费体验产品化 | 竖滑信息流、动态圆环、意图搜、封面/亮点、发布者页、Demo |
| **M2** | 公开可刷网站 | Actions 定时 refresh → GitHub Pages；`publish-site` |
| **M3** | 登录 + UGC API | FastAPI；GitHub 登录认领仓库；发帖进审核；混排 Feed；发布页 |
| **M3.5** | 动态圆环 = 关注动态 | 去掉筛选式动态圆环；关注 Builder/行业（localStorage）；入口 A–F；圆环看最新 |
| **M3.6** | full/lite 双变体 + picker 嵌入 | `variant`；`publish-site`→`index.html`+`embed.html`；picker「去 GitHub 发现」子页 |
| **M3.7** | 首访收敛 + 全量免费 | 废止每天 8 条；价值主张；卡片三区；可 Skip 的 5 步引导；发布 tab 重新露出 |
| **M4** | 生产级云服务 | API 常驻部署（Railway 等）、正式 OAuth、赞藏云同步、审核/举报 |
| **M5** | 增长与生态 | 个性化增强、创作者主页增强、与 skill-picker 联动安装指引（仍不代装） |

---

## 9. 验收标准（摘要）

### 前端

- [x] 底栏仅「发现 / 发布 / 我的」  
- [x] 空场景/栏目 pills 不展示  
- [x] 动态圆环 = 关注动态（非 Skills/AI/开源筛选）；有引导环与「最新进顶部圆环」提示  
- [x] 可关注 Builder / 行业（localStorage）；入口见 §5.4.2  
- [x] pills 承担行业/二级/栏目筛选（与动态圆环分工）  
- [x] 卡片含「解决」+ 要点，无强迫阅读大段正文  
- [x] 无功能的 `···` 不出现  
- [x] 点击作者进入发布者主页（含 Feed 内作品 + GitHub 仓库尝试整合）  
- [x] 主 CTA 仅为打开 GitHub  
- [ ] 每次产品调优已回写本 PRD（§0 / §13）——流程项，持续生效

### 后端 / 管道

- [ ] `refresh` 可产出非空 Feed（或明确漏斗解释）  
- [ ] Pages 定时更新可访问  
- [ ] `api` 在 DEV_AUTH 或 OAuth 下可发帖并在 `/api/feed?source=ugc` 可见  
- [ ] 单元测试通过（`python -m unittest discover -s tests`）  

### 硬边界

- [ ] 无 install 到宿主 skills 目录的 API/文案  

---

## 10. 风险与依赖

| 风险 | 缓解 |
|---|---|
| GitHub API 限流 | Token、缓存 TTL、探测上限 |
| OG 图竖屏裁切 | contain + 场景色底（动态全屏） |
| 静态站赞藏不同步 | M4 云同步；现阶段 localStorage 明示 |
| OAuth 未配 | `SKILLFEED_DEV_AUTH` 本地通路 |
| UGC 质量 | 复用 parse + 场景；后续 pending 审核 |

---

## 11. 文档与代码索引

| 类型 | 路径 |
|---|---|
| 本 PRD | `docs/PRD.md` |
| 场景/语料方向 | `docs/product-corpus-and-taxonomy.md` |
| 后端代码 | `server/` |
| 前端生成 | `feed_dashboard.py` |
| 引擎入口 | `skillfeed.py` |
| Agent Surface / GEO | `geo.py` · 仓库根 `SKILL.md` |
| 亮点提炼 | `highlights.py` |
| 环境变量示例 | `.env.example` |
| Pages 工作流 | `.github/workflows/pages.yml` |
| Agent 安装说明 | `AGENTS.md` |

---

## 12. 附录：开发现状对照（截至 2026-07-28）

| 里程碑 | 状态 | 说明 |
|---|---|---|
| **M0 本地发现引擎** | ✅ 完成 | refresh/corpus/gates/scene/rank/serve；单测覆盖 |
| **M1 消费体验产品化** | ✅ 基本完成 | 竖滑 Feed、动态圆环、亮点卡、发布者页、Demo；个别文案/缓存体验可继续打磨 |
| **M2 公开可刷网站** | ✅ 完成 | Actions → Pages 已上线并可定时刷新 |
| **M3 登录 + UGC API** | 🟡 上线中 | 代码齐；阿里云 Nginx 反代 `/publish` `/auth` `/api`；缺生产 GitHub OAuth Client 填进服务器 `.env` |
| **M3.5 动态圆环=关注** | ✅ 前端已落地 | 动态圆环=关注 Builder/行业最新；入口：卡片关注/场景标签/引导环/发布者页/我的；提示「最新进顶部圆环」；pills 承担行业筛选 |
| **M3.6 full/lite + picker** | ✅ 已落地 | `build_feed_html(variant=)`；本机 `feed.html`+`feed.lite.html`；站点 `index.html`+`embed.html`；skill-picker 第三 tab 嵌入 lite |
| **M4 生产级云服务** | 🟡 起步 | skillfeeder.cn 同机 FastAPI（127.0.0.1:8787），不是 Railway；官方后台 `/op` |
| **M5 增长与生态** | 🟡 起步 | Agent Surface（llms.txt / geo API / 根 SKILL.md）已落地；第三方目录提交仍是人工 |

**综合阶段判断：处于 M2 已交付、M3「可本地跑通 / 待上线」、M3.5 关注动态圆环已落地的过渡期（约产品成熟度 70%–75%）。**

### 已交付能力清单

- 多源发现管道 + 门禁 + 场景 + 排序 + corpus  
- 公开站：https://469910093-ui.github.io/skillfeed/  
- 前端：意图搜、**动态圆环=关注动态**、pills=行业/栏目筛选、关注入口与顶部圆环引导、发现/发布/我的、解决+亮点、发布者主页、打开 GitHub  
- 后端骨架：GitHub OAuth（或 DEV_AUTH）、发帖、混排 Feed、SQLite  

### 明确缺口（相对完整 PRD）

1. 审核通知代码已接通；运营须在 `/op`「页面配置」粘贴飞书自定义机器人 webhook（或写 `SKILLFEED_REVIEW_WEBHOOK`），否则新投稿不会推 IM  
2. 赞/藏/关注仍主要在 **浏览器 localStorage**，未与账号云同步（关注上云属 M4）  
3. 举报、创作者面向的数据看板未做；官方运营后台 `/op` 已覆盖数据 / **路径（含分渠道与按日自然流）** / 审批 / 文案与 logo  
3b. 微信服务号 / 短信通道生产未配齐前，登录页只露出 GitHub 主按钮，并提示内置浏览器走不通；第二钥匙绑定代码已支持同一 `users.id`  
4. README 部分交互说明可能落后于 PRD——**以本 PRD 为准**并持续对齐  

---

## 13. 变更日志（调优必记）

> 每条调优一行：日期 · 摘要 · 影响模块。细节以正文章节为准。

| 日期 | 摘要 | 影响 |
|---|---|---|
| 2026-09-22 | 公开货架只注入用户可见字段（去 completeness 等运营键）；跨境包 blurb 改为「从选品做到利润复盘…」 | §5.1、`feed_dashboard.py`、`docs/packs/shelf_catalog.json` |
| 2026-09-22 | 召回落地：只登 GitHub 不能外发；发现流/我的出绑定微信·手机条；有收藏出站内召回条；`POST /api/me/email` 同意后存邮箱（掩码，暂不发信） | §6.2、`feed_dashboard.py`、`server/db.py`、`server/app.py`、`login.html` |
| 2026-09-22 | 底栏加「一站式配齐」付费场景包货架框架：首波货架/跨境/短剧/营销/数据分析；详情 HOWTO 八节壳 + 购买登录门禁；§3.1 补效率·数据分析；lite 隐藏该 tab | §3.1、§4、§5.1、`feed_dashboard.py`、`publish.html` |
| 2026-09-22 | 游客身份接登录态：进站发/存 `device_token`，登录后自动 `claim` 并档；`devices` 落首触渠道；`/op` 用户卡展示游客设备抓手 | §6.2、`feed_dashboard.py`、`server/db.py`、`admin.html` |
| 2026-09-22 | `/op` 数据页 KPI 卡片可下钻：用户/备份就地明细；待审·上架·拒绝·全部跳审批；今日事件/会话跳路径 24h | §6.2、`admin.html`、`/api/op/users` `/backups` `/events/today` |
| 2026-09-22 | 进站渠道归因：`session_start` 落 UTM/referrer/landing/channel；`/op` 路径 tab 加分渠道 KPI、按日 SEO/GEO 对照与 CSV 字段，便于看自然流 | §6.2、`server/attribution.py`、`server/db.py`、`feed_dashboard.py`、`admin.html` |
| 2026-09-22 | 「一站式配齐」全站用户文案 stop-slop：去运营口吻（待定价/已点名/可借用）、亮点与环节说明改短直说 | §5.1、`feed_dashboard.py`、`docs/packs/shelf_catalog.json` |
| 2026-09-22 | 「一站式配齐」环节区改电商详情式纵向大图（序号轨 + 卡片 + 短说明），并前置为核心卖点；去掉「可卖·材料齐」等运营字段上屏 | §3.1、§5.1、`feed_dashboard.py`、`docs/packs/shelf_catalog.json` |
| 2026-09-22 | 「一站式配齐」亮点改可读长句 + 青绿图标单列营销卡（更醒目） | §5.1、`feed_dashboard.py` |
| 2026-09-22 | 用户可见文案禁草稿/开发者向说明；「一站式配齐」导语定为「持续扩充中」 | §5.1、`feed_dashboard.py`、`.cursor/rules/no-draft-user-copy.mdc` |
| 2026-09-22 | 「一站式配齐」货架分组「效率」改标为「数据分析」 | §3.1、`feed_dashboard.py` |
| 2026-09-22 | 「一站式配齐」商详环节改成编号箭头示意图；标题改为「包含哪些环节？」；亮点为短句双列营销卡 | §3.1、§5.1、`feed_dashboard.py` |
| 2026-09-22 | 「一站式配齐」商详亮点改短句+双列营销卡（安全/全流程/省空间/包教会）；工作流只留步骤芯片并拆出竞品分析·追踪；去掉核心能力整块 | §3.1、§5.1、`feed_dashboard.py`、`docs/packs/shelf_catalog.json`、`scripts/sync_packs_shelf.py` |
| 2026-09-22 | 「一站式配齐」商详改卖点页：飞书「包-*」表灌入 `shelf_catalog.json`；只讲为什么成套/解哪些卡点，八节手册锁住购买后解锁，禁止展开全文散装下 | §3.1、§5.1、`docs/packs/shelf_catalog.json`、`scripts/sync_packs_shelf.py`、`feed_dashboard.py` |
| 2026-09-22 | 底栏「一站式配齐」标签禁止拆字换行（去掉 `max-width: 4.8em`，改 `white-space: nowrap`） | §5.1、`feed_dashboard.py` |
| 2026-09-22 | 空态肥嘚改回完整透明团子（156×120），去掉带蓝底缺口的残缺磁贴 | §5.1、`feed_dashboard.py` |
| 2026-09-22 | 空态肥嘚曾误用定稿磁贴 `logo-feide-empty.png`（已回退） | §5.1、`feed_dashboard.py` |
| 2026-09-22 | 空态肥嘚晃动动画去掉 120×120 正方形硬框 | §5.1、`feed_dashboard.py` |
| 2026-09-21 | GEO 二次优化：独立 `/about.html` `/faq.html` `/compare.html` 给爬虫；JSON-LD 补 Organization；llms blockquote<200 + Key Facts；robots 补 OAI-SearchBot 等 AI 爬虫；登录/发布页补 Twitter 与 WebPage | §6.3、`geo.py`、`server/app.py`、登录/发布模板、Nginx/Pages 部署清单 |
| 2026-09-21 | 浏览器小标改高分辨率缩小（192 PNG + 多尺寸 ICO），去掉平滑发糊；页头肥嘚加大到 52×40 | §5.1、`scripts/make_brand_icons.py`、`feed_dashboard.py` |
| 2026-09-21 | 补浏览器 tab / 主屏小标：`publish-site` 落盘 `/favicon.ico` `/favicon.png` `/apple-touch-icon.png`（肥嘚慵懒躺沙发造型），首页与登录/发布页挂 link，阿里云/Pages 同步拷贝 | §5.1、§6.3、`geo.py`、`server/app.py`、登录/发布模板、`pages.yml` |
| 2026-09-21 | 排序叠加路径判断：不改 G/P/F/N；冲突给置信度并 sticky；近邻同分才按 reliable/task/publisher 二次键。笔记 https://xhslink.cn/o/8fvgNlMau1U | §6.1、`ranking_path.py`、`server/app.py` |
| 2026-09-21 | SEO 与 Agent 话术对齐：中文 TDK、OG、`/og.png`、放行登录/发布着陆页；标题不再只写品牌名 | §6.3、`geo.py`、`feed_dashboard.py`、`login.html`、`publish.html` |
| 2026-09-21 | Agent Surface 加宽推荐话术：发现者侧强调安全/可靠/已过滤高星；发布者侧强调可靠流量渠道。覆盖「荐靠谱 skill」「我的产品怎么被发现」等真实问法 | §1、§3、§6.3、`geo.py`、`SKILL.md` |
| 2026-09-21 | Agent Surface 落盘改为 UTF-8 无 BOM + LF；Nginx 必须带 `charset=utf-8`，避免中文 Windows 把 `/llms.txt` 当 GBK | §6.3、`geo.py`、`scripts/nginx-skillfeeder.conf` |
| 2026-09-21 | 加 Agent Surface / GEO：`/llms.txt`、消毒目录、FAQ/对比、公开 `/api/geo/skills`、首页 describedby+JSON-LD+noscript、根 `SKILL.md`；对外品牌统一 SkillFeeder。Pages 仍 0 条壳，目录只在主站 | §1、§6.1、§6.3、`geo.py`、`server/app.py`、`feed_dashboard.py`、`scripts/nginx-skillfeeder.conf` |
| 2026-09-21 | 场景包装配收成可复用工作流：采集→编目→打标→飞书候选→HOWTO/QUALITY；Agent 入口 `packaging-scene-skills` | §3.1、`docs/packs/PACKAGING.workflow.md`、`.cursor/skills/packaging-scene-skills` |
| 2026-09-21 | 变现供给侧按使用场景拆包：货架/跨境/内容/直播电商 + 资讯/短剧/营销广告/平面设计自媒体；飞书一张总览+八张场景表；未点名 Skill 标待补采，禁止编造 | §3.1、飞书场景包 Base |
| 2026-09-19 | 演示稿封面用「把 GitHub 做成小红书一样有趣」作开场钩子；产品首页价值主张仍是「每刷一下，就快人一步」 | `docs/pitch/index.html`、§1 |
| 2026-09-19 | 定时发布漏写 `api_base` 把主站发布 tab 冲成「静态镜像」：`--full` 默认写入 `https://skillfeeder.cn`；前端同源回退；Aliyun 部署缺 `api_base` 则拒绝覆盖 | §5.1、`feed_dashboard.py`、`skillfeed.py`、`.github/workflows/pages.yml` |
| 2026-09-17 | 手机登不上：OAuth 改为 200 中转页再跳 GitHub/微信（避免 302 丢 Cookie）；登录页把 GitHub 当主按钮，点明微信/小红书/抖音内置浏览器走不通 | §6.2、§7.2、§12、`server/auth.py`、`server/app.py`、`login.html`、`publish.html`、`feed_dashboard.py` |
| 2026-09-17 | 收藏跨设备一致性（D2：列表读云端）：`/auth/me` 返账号 `saved`/`liked` full_name 数组（跨设备聚合，`server/db.py::user_saved_full_names`）；前端 `effectiveSavedSet()` 让「查看收藏」列表与计数同源、长度恒等，saved 模式只列收藏不再混点赞 | §5.4.5、§6.2、`server/app.py`、`server/db.py`、`feed_dashboard.py`、`tests/test_server_api.py`、`tests/test_feed_dashboard.py` |
| 2026-09-17 | 安全基础设施（轻量）：新增 `.github/dependabot.yml`（pip + github-actions 每周扫、不自动合）；`AGENTS.md` 补安全规范（凭据不入库 / 飞书 base_token 非密钥但导出产物不入库 / `_tmp_` 不入库 / 外部调用必带 timeout / Push Protection 建议）；`.gitignore` 扩到根级 `_tmp_*` | §6.0、`AGENTS.md`、`.github/dependabot.yml`、`.gitignore` |
| 2026-09-17 | PRD 补「凭据不入库」铁律（§6.0）与登录页 URL 说明（§6.2：`loginUrl` 用 `API_BASE`，无独立 `site_home`，Medium #7 误报） | §6.0、§6.2 |
| 2026-09-17 | 用户财产不绑死 GitHub：已登录可绑微信/手机到同一户口；「我的」导出账本；SQLite 每日备份 | §6.2、`server/db.py`、`server/backup.py`、`feed_dashboard.py` |
| 2026-09-17 | 管理后台加「路径」：游客也可 `POST /api/events`；会话操作链 + 时间线 + CSV，给后续分析用 | §6.2、§12、`server/app.py`、`server/db.py`、`admin.html`、`feed_dashboard.py` |
| 2026-09-17 | 「我发布的」第二次点击不再切发现流重刷：始终预览当前这条卡 | §6.2、`feed_dashboard.py` |
| 2026-09-17 | 修 `/op` 反代：同时接 `/op` 与 `/op/`，并加 `/admin`、卡片短链 `/p/{仓库名}`，避免聊天里 `::` 截断和斜杠互踢 | §6.2、`scripts/nginx-skillfeeder.conf`、`server/app.py` |
| 2026-09-17 | 官方管理后台 `/op`：数据 / 审批 / 页面配置（口号·搜索占位·logo·审核 webhook）；「我发布的」点开看卡片（已上架跳发现流，审核中出预览）；个人页去掉「发现站」说明行 | §5.1、§6.2、§12、`server/templates/admin.html`、`feed_dashboard.py` |
| 2026-09-17 | 补投稿待审通知：`SKILLFEED_REVIEW_WEBHOOK` 或后台保存的 webhook 推飞书/通用 webhook；不配则只落库 | §6.2、§12、`server/notify.py` |
| 2026-09-16 | 获客定案：发现流全量免费，废止「非会员每天 8 条」；价值主张改为「每刷一下，就快人一步」；卡片拆成图 / 只读总结 / 可点互动三区；full 首次进入出 5 步可 Skip 引导（关注落点、下滑、互动、GitHub、发布）；发布 tab 重新露出 | §1、§2.3、§5.1、§5.2、§7.1、§8、`entitlement.py`、`feed_dashboard.py`、`login.html` |
| 2026-09-17 | 动手上线 UGC：游客可拉 `/api/feed`（只含已过审）；投稿必须 GitHub 登录且 login=owner；阿里云 Nginx 反代 `/publish` `/auth` `/api` `/op` | §6.2、§7.2、§12、`server/app.py`、`docs/deploy-api.md` |
| 2026-09-17 | 新增 GitHub 分片搜索：捞 `stars>=2000` 且探测为 skill 形的仓，写入飞书底表并灌主 Feed（补上仅靠 Wiki/榜单会漏的仓） | §6.1、`scripts/harvest_github_2k_skills.py` |
| 2026-09-16 | 信息流不再只收 skill：底表里可判定的 MCP（仓名含 mcp / 描述含 MCP Server·Model Context Protocol，星≥20）也进主 Feed，`kind=mcp`；不假装有 SKILL.md | §6.0、`gate_waytoagi_feed.py`、`ingest_waytoagi_candidates.py`、`feed_pack.py` |
| 2026-09-14 | 修复肥嘚 logo 脸部丢失：团子头部为浅紫渐变（S 0.1-0.35）与磁贴背景同色系，颜色阈值不可用——改为「裁剪团子主体区域 + AI 语义抠图 + 连通域」，闭眼线条/嘴/腮红完整保留；logo 源图提至 512px 保证小尺寸清晰 | §5.1 顶栏/页脚 logo、`feed_dashboard.py`、`docs/brand/assets/logo-feide-transparent.png` |
| 2026-09-14 | 修复肥嘚 logo 右脚截断：改用「饱和度软阈值 + 连通域」从用户原图重新抠团子本体（排除磁贴底/星星/终端卡片），顶栏/页脚 logo 换为完整透明异形团子（160×125，非圆形裁切） | §5.1 顶栏/页脚 logo、`feed_dashboard.py` |
| 2026-09-10 | 左上角/页脚 S 图形标替换为肥嘚团子头像（base64 内联 PNG，28px/20px，圆形裁切）；配色变量已对齐品牌令牌 | §5.1 顶栏/页脚 logo、feed_dashboard.py |
| 2026-09-10 | 顶栏/页脚字标前新增 S 图形标（内联 SVG，紫→青→薄荷渐变 `#9860e7→#49aaeb→#64e2d4`，与 `.feeder` 同源）；`.logo` 改 flex 布局；同步生成纯白底 S 图形版（favicon/小头像）与横版 Banner | §5.1 顶栏、`feed_dashboard.py` |
| 2026-09-10 | 定数据分层：飞书资源清单=全量底表（不论是否 skill）；skill-feed 只按门禁从底表筛入信息流。底表有 Feed 无=正常 | §4 IA、§6.0、`AGENTS.md`、`docs/waytoagi-kb-batch.md` |
| 2026-09-09 | 底栏收敛为**四入口**（发现/主题分类/发布/我的）并做成真 `role=tablist`；场景 chips 从发现页首屏移到「主题分类」tab（只在筛选中回归）；发布接 `POST /api/posts`；我的接 `/auth/me` + `/api/posts/me` + `/api/profile/reactions`；新增一键回到顶部；`?tab=` / `?scene=` / `?l2=` 深链 | §5.1、`feed_dashboard.py`、`tests/test_feed_dashboard.py` |
| 2026-09-08 | 策展源补 GitHub The Download 点名的 MCP/Skills/Agent 仓；`ingest_the_download.py` 灌 corpus+飞书；catalog 强制探测 | §4 信源、`catalog_sources`、`docs/the-download-mcp-skills.md`、bitable |
| 2026-08-11 | 补齐产品设计供给侧：设计类种子强制探测、monorepo 展开 frontend-design/figma/shadcn、「产品设计」意图映射真实 skill 名 | `catalog_sources` / `skill_detect` / `scene` / `intentTokens` |
| 2026-08-11 | Feeds 关键词改为真实词表命中（最多 2 个），禁止中文滑动切碎造「产品设/品设品」假词 | `compressIntent` / `intentTokens` |
| 2026-08-10 | 新增 `catalog`（awesome / skills.sh / 官方仓）与 `xiaohongshu`（媒讯助手/Chrome 采集）发现源；`xhs-crawl` CLI；源 chip 展示 | §4、§6.1、`catalog_sources.py`、`xiaohongshu.py`、`skillfeed.py` |
| 2026-08-03 | 长意图自动提炼短关键词（输入框 maxlength、粘贴/回车/URL 预填压缩、关键词 chips）；匹配与 GitHub 空态都用短词 | `compressIntent` / `applyIntentInput` |
| 2026-08-03 | 意图匹配支持中文二元组 + 去 AI 味同义（slop/stop-slop）；避免「去掉文案的AI味」空命中 | `intentTokens` / `intentMatch` |
| 2026-08-03 | 修正 GitHub 空态搜索：`filename:` → `path:**/SKILL.md`（否则会搜到正文提到该字样的无关文件） | `githubSearchUrls` |
| 2026-08-03 | Feed 空结果时提供 GitHub 网页搜索兜底；不代装 | §5.2 空态、`feed_dashboard.emptyHtml` |
| 2026-07-28 | M3.6：页面拆 full（独立网页）/ lite（picker 子页，无关注·发布·我的）；`publish-site` 双写 index+embed；`?q=` 意图预填；skill-picker 第三 tab「去 GitHub 发现」 | §1、§3、§8、§12、`feed_dashboard.py`、`skillfeed.py`、picker `discover.py`/`dashboard.py` |
| 2026-07-28 | 订立 §0 变更纪律：产品调优必须同批回写 PRD | 流程 / 全文档 |
| 2026-07-28 | M3.5：动态圆环从模式/场景筛选改为关注 Builder+行业最新动态；pills 专司筛选；多入口关注 +「最新进顶部圆环」引导 | §5.0–5.4、§8、§9、§12、`feed_dashboard.py` |
| 2026-07-28 | 底栏收敛为发现/发布/我的；卡片解决+亮点；发布者主页；UGC API 骨架；Pages 定时站 | M1–M3 既有交付 |
