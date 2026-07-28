# skill-feed 产品需求文档（PRD）

| 字段 | 内容 |
|---|---|
| 产品名 | skill-feed |
| 版本 | v0.4.0（相对本仓库当前实现） |
| 文档状态 | **唯一产品真相源（Source of Truth）** |
| 仓库 | https://github.com/469910093-ui/skillfeed |
| 公开发现站 | https://469910093-ui.github.io/skillfeed/ |
| 关联产品 | [skill-picker](https://github.com/469910093-ui/Skill-picker)（本机已装 skill 的扫描/匹配） |
| 更新日期 | 2026-07-28 |

---

## 0. 变更纪律（强制）

> **所有产品调优必须落到本文档。**  
> 代码可以领先实现，但**不得**长期存在「只改了前端/排序/文案、PRD 没写」的状态。

### 0.1 适用范围

以下任一变化，**同一轮改动内**必须更新本 PRD（至少改需求正文 + §13 变更日志；必要时改里程碑/附录现状）：

| 类型 | 示例 |
|---|---|
| 信息架构 / 导航 | Stories 职责、底栏、pills、页面增减 |
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

**skill-feed** 是 Instagram 板式的 **Agent Skill / 开源线索发现站**：多源抓取 → 门禁 → 个性化排序 → 无限信息流 → **打开 GitHub**。  
用户可浏览官方发现流，并（规划中/进行中）登录后发布自己的 skill（UGC）。

同一生成器产出两种页面变体（`ui.variant`）：

| 变体 | 产物 | 用途 |
|---|---|---|
| **full** | `feed.html` / `site/index.html` | **独立网页产品**（Stories/关注/发布/我的，可接 `api_base`） |
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

---

## 3. 用户与场景

| 角色 | 核心场景 | 主路径 |
|---|---|---|
| 发现者 | 「有没有 skill 能做周报 / 去 AI 味」 | 打开站 → 搜意图 / pills 筛 → 看卡片 → 打开 GitHub；对感兴趣作者/行业点关注 → 用 Stories 追最新 |
| 关注者 | 「我盯的人/行业有没有新东西」 | Stories 圆环 → Builder/行业最新动态 → 打开 GitHub |
| 收藏者 | 先攒着以后用 | 赞/书签 →「我的」看本机收藏 |
| 创作者（UGC） | 发布自己的 skill 让别人发现 | 登录 → 发布 → 出现在混排 Feed |
| 维护者（你） | 内容新鲜、门禁可控 | CLI refresh / Actions 定时部署 / API 配置 |

与 **skill-picker** 分工：

```text
skill-picker 找技能（本机）──匹配为空──► 看板「去 GitHub 发现」
                                      │ 嵌入 skill-feed lite
                                      ▼
                              打开 GitHub 自行安装 ──► skill-picker scan

skill-feed full（独立站）── Stories/关注/UGC（可选 API）──► 打开 GitHub
```

---

## 4. 产品信息架构

```text
┌──────────────────────────────────────────────┐
│ 发现站前端（静态 HTML / 可连 API）              │
│  搜意图 · Stories(关注) · pills(筛选) · 卡片   │
│  底栏：发现 / 发布 / 我的                       │
│  发布者主页 · Story 全屏 · Demo 巡演            │
└───────────────┬──────────────────────────────┘
                │ api_base（可选）
┌───────────────▼──────────────────────────────┐
│ 云端 API（FastAPI + SQLite）                   │
│  GitHub OAuth · 发帖 UGC · /api/feed 混排     │
└───────────────┬──────────────────────────────┘
                │ 官方索引
┌───────────────▼──────────────────────────────┐
│ 发现引擎 + 定时任务（CLI / GitHub Actions）     │
│  trending · HelloGitHub · GitHub Search       │
│  gates · scene · rank · corpus · publish-site │
└──────────────────────────────────────────────┘
```

---

## 5. 前端需求（完整）

### 5.0 信息架构铁律：Stories ≠ Pills

**现状问题：** Stories 圆环与下方 pills 都在做「模式/场景/栏目筛选」，功能重复，圆环没有「关系」价值。

**重新分工（必须遵守）：**

| 模块 | 产品职责 | 不是什么 |
|---|---|---|
| **Stories 圆环** | **关注流入口**：已关注 Builder 的最新动态、已关注行业的最新动态；优先观看 | 不是全站筛选器 |
| **Pills（pillar）** | **当前发现 Feed 的筛选**：场景二级 / 栏目 /（可选）内容形态 | 不是关注关系 |
| **主 Feed** | 发现浏览（未关注时默认推荐；可被 pills 收窄） | — |

```text
Stories = 我关心的人 / 行业 · 有没有新东西（关系 + 时效）
Pills   = 我正在逛发现流时 · 怎么收窄（会话内筛选）
```

### 5.1 页面与导航

| 模块 | 功能说明 | 优先级 |
|---|---|---|
| 发现 Feed | 无限下滑；嵌入 `feed.json`；本地/Pages 可独立打开 | P0 |
| 意图搜索 | 顶栏输入，实时过滤 name/desc/场景等 | P0 |
| **Stories（关注动态）** | 见 5.4；圆环 = 关注的 Builder / 行业；点开看「最新」Story 或时间线 | P0 |
| **Pills** | 仅作发现筛选：二级场景、栏目等；**空则隐藏**；不再放 Skills/AI/开源模式（与 Stories 脱钩） | P0 |
| 信息流卡片 | 见 5.2 | P0 |
| 底栏三入口 | **发现 / 发布 / 我的** | P0 |
| 发布 | 跳转 `api_base/publish` | P0 |
| 我的 | 赞/藏 + **关注管理**（Builder / 行业列表）+ API/登录入口 | P0 |
| 发布者主页 | Feed 内作品 + GitHub 仓库 + **关注/取消关注 Builder** | P0 |
| Demo 巡演 | 顶栏播放键或 `?demo=1` | P1 |
| 反馈 | 赞/踩/打开 GitHub；静态站 localStorage | P1 |

### 5.2 信息流卡片（货架单元）

卡片必须让用户 **3 秒内** 回答：「解决什么问题？有什么亮点？要不要去 GitHub？」

| 区块 | 要求 |
|---|---|
| 发布者行 | 头像 + skill 名 + `@owner`；点进发布者主页；可快捷「关注」；无 `···` |
| 封面 | GitHub OG；失败短文案兜底 |
| 场景标签 | 一/二级；标签可点「关注该行业」（见 5.4） |
| **解决** / **亮点** | 一句话 + 3–4 要点 |
| SKILL.md 链接 | 看全文 |
| 互动 | 赞、踩、收藏 |
| 主 CTA | **打开 GitHub** |

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
- **无：** Stories、关注、发布、我的、`api_base`、Demo  
- picker：`discover.py` → `~/.skill-picker/discover.html`；看板第三 tab iframe；空匹配 CTA 切入  
- 公开回退：`https://469910093-ui.github.io/skillfeed/embed.html`

### 5.4 关注体系：Builder + 行业（Stories 的数据来源）

#### 5.4.1 对象定义

| 关注对象 | ID | 「最新动态」定义（MVP） |
|---|---|---|
| **Builder** | GitHub `owner` / 日后 UGC `author_login` | Feed/corpus 中该作者条目，按刷新时间/排序分取 Top N；Story 全屏轮播 |
| **行业** | 一级场景 `scene`（如 `content` 内容创作） | 该场景下最新/高分条目 Top N；Story 全屏轮播 |

可选后续：行业二级、HelloGitHub 栏目「语言赛道」——**不进 Stories**，只留在 pills，避免再次重叠。

#### 5.4.2 用户在哪里「关注」（入口地图）

必须有多处、低摩擦入口；否则 Stories 永远是空的。

| # | 入口位置 | 动作 | 对象 |
|---|---|---|---|
| A | **发布者主页** | 主按钮「关注 Builder」/「已关注」 | Builder |
| B | **卡片发布者行** | 小号「关注」或长按头像菜单（MVP 可用行内按钮） | Builder |
| C | **卡片场景标签** | 点标签 → 浮层「查看该行业 Feed」+「关注行业」 | 行业 |
| D | **发现 Feed 空 Stories 引导** | 未关注时圆环位展示「发现 Builder」「发现行业」引导环，点进推荐列表 | 两者 |
| E | **我的 → 关注** | 管理列表：取消关注；展示已关注 Builder/行业 | 两者 |
| F | **行业落地（轻页）** | 从标签/引导进入「内容创作」页：说明 + 该行业热卡 +「关注行业」 | 行业 |

**推荐默认路径（冷启动）：**

1. 用户刷发现 → 点感兴趣卡片的作者 → 发布者页点关注 → Stories 出现该 Builder 环  
2. 或点卡片上「内容创作」标签 → 关注行业 → Stories 出现行业环  
3. 「我的」可清理关注，避免圆环膨胀  

#### 5.4.3 Stories 圆环交互

| 环类型 | 展示 | 点击 |
|---|---|---|
| 关注动态（总览） | 可选第一枚「关注」总环 | 仅看已关注 Builder∪行业的合并最新流 |
| Builder 环 | 头像 initials / 日后真实头像；有更新时亮环 | 该 Builder 最新 3–5 条 Story |
| 行业环 | 行业色 + 二字简称 | 该行业最新 3–5 条 Story |
| 引导环（未关注） | 「+ Builder」「+ 行业」 | 打开推荐关注列表（Feed 内高频 owner / 全场景） |

**禁止：** 再在 Stories 放「全部 / Skills / AI / 开源」等与 pills 同质的筛选环。

#### 5.4.4 与后端演进

| 阶段 | 关注存储 | Stories 数据 |
|---|---|---|
| 现在可做（M3.5） | localStorage | 前端按 owner/scene 从嵌入 `FEED` 过滤 |
| M4 | 账号云同步 `follows` 表 | API `GET /api/following/feed`；登录多端一致 |

---

## 6. 后端与数据管道需求（完整）

### 6.1 发现引擎（CLI，可本机 / CI）

| 命令 | 职责 |
|---|---|
| `corpus` | HelloGitHub 等灌入本地知识库（只增不删） |
| `refresh` | trending + HG + Search → 探测 SKILL.md → 门禁 → 场景 → 排序 → `feed.json` + HTML |
| `build` | 不联网，用已有数据重生 Feed HTML |
| `publish-site` | 导出 `site/index.html` + `feed.json`（Pages） |
| `serve` | 本机预览 + `/api/feedback` |
| `api` | 启动云端 FastAPI |
| `check` / `feedback` | 门禁检查与反馈汇总 |

**数据源**

| source | 角色 |
|---|---|
| `github.com/trending` | 热度爆发 |
| `hellogithub` | Skills / AI 月刊稳定供给 |
| `github-search` | SKILL.md / agent-skills 召回（建议 Token） |
| `corpus` / soft | 知识库补货线索卡 |
| `ugc` | 用户发布（API） |

**门禁与排序（要点）**

- 门禁：来源白名单、星标（部分源豁免）、解析质量、相关性等（`gates` + `gate_profile`）  
- 场景：一级 + 二级 taxonomy（`scene`）  
- 排序：`rel` + 意图 + feedback 画像 → `personal_score`（`rank`）  
- 卡片文案：`highlights.extract_highlights` → `problem` + `highlights[]`

**定时公开站**

- GitHub Actions：每 6 小时 `refresh` + `publish-site` → GitHub Pages  
- 数据目录可用 `SKILLFEED_HOME` 覆盖  

### 6.2 云端 API（`server/`）

| 能力 | 接口/页 | 说明 |
|---|---|---|
| 健康检查 | `GET /health` | oauth / dev_auth 状态 |
| GitHub 登录 | `GET /auth/github` → callback | OAuth；本地可 `SKILLFEED_DEV_AUTH=1` |
| 当前用户 | `GET /auth/me` | |
| 登出 | `POST /auth/logout` | |
| 发布 UGC | `POST /api/posts`、表单 `/api/posts/form`、页 `/publish` | 解析 SKILL.md、打场景、入库 |
| 我的帖子 | `GET /api/posts/me` | |
| 反应 | `POST /api/posts/{id}/react` | like/save/bad |
| 混排 Feed | `GET /api/feed` | UGC + 官方 `feed.json` URL |

**配置（环境变量，见 `.env.example`）**

| 变量 | 用途 |
|---|---|
| `SKILLFEED_PUBLIC_URL` | 对外 URL / 前端 api_base / OAuth 回调前缀 |
| `SKILLFEED_GITHUB_CLIENT_ID/SECRET` | OAuth App |
| `SKILLFEED_SESSION_SECRET` | 会话签名 |
| `SKILLFEED_OFFICIAL_FEED_URL` | 官方 Pages feed.json |
| `SKILLFEED_CORS_ORIGINS` | 跨域 |
| `SKILLFEED_DB` | SQLite 路径（默认 `~/.skill-feed/server.db`） |
| `SKILLFEED_DEV_AUTH` | 本地免 OAuth |
| `SKILLFEED_HOME` | 发现引擎数据根目录 |

**存储（MVP）**

- SQLite：`users` / `posts` / `reactions`  
- 生产可迁 Postgres（未作为当前交付）

---

## 7. 关键用户旅程（端到端）

### 7.1 发现者（未登录）

1. 打开 Pages 或本机 serve  
2. 搜意图或点 pills 筛选；或点 Stories 看已关注动态 
3. 看「解决 + 亮点」决策  
4. 打开 GitHub；可选赞/藏  
5. 点作者进发布者主页浏览更多  

### 7.2 创作者（UGC）

1. 配置并启动 API，前端配置 `api_base`  
2. 底栏「发布」或「我的」→ GitHub 登录  
3. 粘贴 SKILL.md / 仓库链接 → 发布  
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
| **M1** | 消费体验产品化 | IG 信息流、Stories、意图搜、封面/亮点、发布者页、Demo |
| **M2** | 公开可刷网站 | Actions 定时 refresh → GitHub Pages；`publish-site` |
| **M3** | 登录 + UGC API | FastAPI OAuth、发帖、混排 Feed、发布页；前端底栏对接 |
| **M3.5** | Stories = 关注动态 | 去掉筛选式 Stories；关注 Builder/行业（localStorage）；入口 A–F；圆环看最新 |
| **M3.6** | full/lite 双变体 + picker 嵌入 | `variant`；`publish-site`→`index.html`+`embed.html`；picker「去 GitHub 发现」子页 |
| **M4** | 生产级云服务 | API 常驻部署（Railway 等）、正式 OAuth、赞藏云同步、审核/举报 |
| **M5** | 增长与生态 | 个性化增强、创作者主页增强、与 skill-picker 联动安装指引（仍不代装） |

---

## 9. 验收标准（摘要）

### 前端

- [x] 底栏仅「发现 / 发布 / 我的」  
- [x] 空场景/栏目 pills 不展示  
- [x] Stories = 关注动态（非 Skills/AI/开源筛选）；有引导环与「最新进顶部圆环」提示  
- [x] 可关注 Builder / 行业（localStorage）；入口见 §5.4.2  
- [x] pills 承担行业/二级/栏目筛选（与 Stories 分工）  
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
| OG 图竖屏裁切 | contain + 场景色底（Story） |
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
| 亮点提炼 | `highlights.py` |
| 环境变量示例 | `.env.example` |
| Pages 工作流 | `.github/workflows/pages.yml` |
| Agent 安装说明 | `AGENTS.md` |

---

## 12. 附录：开发现状对照（截至 2026-07-28）

| 里程碑 | 状态 | 说明 |
|---|---|---|
| **M0 本地发现引擎** | ✅ 完成 | refresh/corpus/gates/scene/rank/serve；单测覆盖 |
| **M1 消费体验产品化** | ✅ 基本完成 | IG Feed、Stories、亮点卡、发布者页、Demo；个别文案/缓存体验可继续打磨 |
| **M2 公开可刷网站** | ✅ 完成 | Actions → Pages 已上线并可定时刷新 |
| **M3 登录 + UGC API** | 🟡 开发完成、未生产化 | `server/` + `/publish` + 混排 API + 前端底栏对接逻辑已有；缺：正式 OAuth 配置、API 常驻部署、公开站默认 `api_base` |
| **M3.5 Stories=关注** | ✅ 前端已落地 | Stories=关注 Builder/行业最新；入口：卡片关注/场景标签/引导环/发布者页/我的；提示「最新进顶部圆环」；pills 承担行业筛选 |
| **M3.6 full/lite + picker** | ✅ 已落地 | `build_feed_html(variant=)`；本机 `feed.html`+`feed.lite.html`；站点 `index.html`+`embed.html`；skill-picker 第三 tab 嵌入 lite |
| **M4 生产级云服务** | ⬜ 未开始 | Railway/Fly 部署、赞藏云同步、审核/举报 |
| **M5 增长与生态** | ⬜ 未开始 | 更强个性化、与 skill-picker 安装指引联动 |

**综合阶段判断：处于 M2 已交付、M3「可本地跑通 / 待上线」、M3.5 关注 Stories 已落地的过渡期（约产品成熟度 70%–75%）。**

### 已交付能力清单

- 多源发现管道 + 门禁 + 场景 + 排序 + corpus  
- 公开站：https://469910093-ui.github.io/skillfeed/  
- 前端：意图搜、**Stories=关注动态**、pills=行业/栏目筛选、关注入口与顶部圆环引导、发现/发布/我的、解决+亮点、发布者主页、打开 GitHub  
- 后端骨架：GitHub OAuth（或 DEV_AUTH）、发帖、混排 Feed、SQLite  

### 明确缺口（相对完整 PRD）

1. API **未**作为公网常驻服务部署；多数用户打开 Pages 时「发布」仍提示未配置 `api_base`  
2. 生产 GitHub OAuth App 未作为默认交付（需你在 GitHub 创建并填 Secret）  
3. 赞/藏/关注仍主要在 **浏览器 localStorage**，未与账号云同步（关注上云属 M4）  
4. UGC 审核流、举报、创作者数据看板未做  
5. README 部分交互说明可能落后于 PRD——**以本 PRD 为准**并持续对齐  

---

## 13. 变更日志（调优必记）

> 每条调优一行：日期 · 摘要 · 影响模块。细节以正文章节为准。

| 日期 | 摘要 | 影响 |
|---|---|---|
| 2026-07-28 | M3.6：页面拆 full（独立网页）/ lite（picker 子页，无关注·发布·我的）；`publish-site` 双写 index+embed；`?q=` 意图预填；skill-picker 第三 tab「去 GitHub 发现」 | §1、§3、§8、§12、`feed_dashboard.py`、`skillfeed.py`、picker `discover.py`/`dashboard.py` |
| 2026-07-28 | 订立 §0 变更纪律：产品调优必须同批回写 PRD | 流程 / 全文档 |
| 2026-07-28 | M3.5：Stories 从模式/场景筛选改为关注 Builder+行业最新动态；pills 专司筛选；多入口关注 +「最新进顶部圆环」引导 | §5.0–5.4、§8、§9、§12、`feed_dashboard.py` |
| 2026-07-28 | 底栏收敛为发现/发布/我的；卡片解决+亮点；发布者主页；UGC API 骨架；Pages 定时站 | M1–M3 既有交付 |
