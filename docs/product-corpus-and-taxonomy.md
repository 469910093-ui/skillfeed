# skill-feed 产品方向：无限下滑 × 离线知识库 × 头部筛选

## 交互原则

- **少点击、多下滑**：默认进入无限 Feed；筛选只在顶栏横滑 chip，不进二级页。
- 主操作仍是 **打开 GitHub**（或打开离线文档详情抽屉——仍尽量不跳页）。
- 「换一批 / 下一条」弱化；用惯性滚动加载下一屏。

## 双层内容架构

```text
┌─────────────────────────────────────────┐
│  Feed（在线推荐流）                       │
│  无限下滑 · 头部筛选 · 场景/栏目 chip     │
└─────────────────┬───────────────────────┘
                  │ 读 / 降级
┌─────────────────▼───────────────────────┐
│  离线知识库 Corpus（本地海量 backup）      │
│  ~/.skill-feed/corpus/                   │
│  · hellogithub/issues/*.md               │
│  · github/repos/<owner>/<repo>/…         │
│  · index.jsonl（可检索元数据）            │
│  持续 sync / 增量扩充                     │
└─────────────────────────────────────────┘
```

| 层 | 职责 |
|---|---|
| Feed | 当下「刷」：排序、筛选、个性化理由 |
| Corpus | 全量留存：HelloGitHub 全刊 + 已爬到的 GitHub skill/README，断网可搜可刷缓存 |

### Corpus 收录范围（建议）

1. **HelloGitHub 全刊**（已有镜像）→ 规范化入库，按栏目打标签  
2. **Skills 专栏 / 含 SKILL.md 的仓库** → 拉 SKILL.md + README 摘要  
3. **AI 栏目候选** → 仅当探测到 skill 形态才进「Skills 库」，否则进「开源浏览库」  
4. 持续扩充：refresh / 定时任务只 **增量** 写入，不删历史（知识库只增）

### 与「只推荐到 GitHub」的关系

- Feed 卡片 CTA：优先打开 GitHub；次要可「看离线摘要」（本地已存则秒开）。
- **不代装**到宿主 skills 目录。

---

## 头部筛选（来自 HelloGitHub 栏目 + Skills 场景）

### 第 0 行：模式（少选项）

| Chip | 含义 |
|---|---|
| 全部 | 混合流（默认） |
| Skills | 仅 agent skill 形态 |
| 开源逛逛 | 语言项目 / 其它（非 skill） |
| AI | 人工智能栏目 + 验过的 skill |

### 第 1 行：Skills 场景一级分类（仅在 Skills / 全部 时出现）

见下一节「场景 taxonomy」。

### 第 2 行：HelloGitHub 语言/栏目（开源逛逛时为主；Skills 模式下可收起）

`Python` `JavaScript` `Go` `Rust` … `人工智能` `开源书籍` `其它`

---

## Skills 场景一级分类（提议）

面向「我此刻要干什么」，不是面向编程语言。

| 一级场景 ID | 中文名 | 典型意图 / 例子 |
|---|---|---|
| `content` | 内容创作 | 文案、短视频、口播、选题、去 AI 味（stop-slop、Viral Writer…） |
| `design` | 设计与视觉 | Figma、图表、白板、PPT 视觉 |
| `data-review` | 数据与复盘 | 周报、BI、活动复盘、指标解读 |
| `engineering` | 工程开发 | 写代码、重构、少写代码（ponytail）、架构 |
| `quality` | Bug 与质量 | 调试、测试、验证、code review、门禁 |
| `collab` | 协作办公 | 飞书、Notion、会议纪要、任务 |
| `research` | 研究与知识 | 学术、精读、文献（academic-research-skills）、笔记库 |
| `agent-tooling` | Agent 工具链 | skill 管理、MCP、工作流、提示词包 |
| `biz-vertical` | 业务垂直 | 电商、出行、营销投放等垂直 skill |
| `other` | 其他 | 暂无法归类；允许用户反馈纠正 |

### 打标规则（落地时）

1. 优先读 `SKILL.md` frontmatter：`category` / `tags` / `description`  
2. 再用规则表（关键词 → 场景），与 skill-picker `rules.json` 思路类似  
3. 低置信进 `other`，Feed 上可点「归类不准」写 feedback  
4. **一级分类先压到 ≤10 个**，二级场景（如「内容创作 → 短视频 / 写作」）Phase 2 再拆

### 和 HelloGitHub 栏目的映射

| HG 栏目 | 默认进 |
|---|---|
| Skills | Skills 库 + 跑场景打标 |
| 人工智能 | 宽召回 → 有 SKILL.md 进 Skills，否则进 AI/开源浏览 |
| `X 项目` / 其它 / 开源书籍 | 开源逛逛库（可不强行场景打标） |

---

## Feed 形态（对应骨架）

- 垂直 **无限列表**（非一屏一卡硬切也可：大卡 + 下方露出下一张）  
- 顶栏两行 chip，滚动时吸顶压缩  
- 每卡：场景 chip + 来源 chip + 一句话 + 匹配理由 + 打开 GitHub  
- 滑到底：从 Corpus 补同筛选条件下的历史精品（backup 感），标注「来自知识库」

## 暂不做什么

- 不代装  
- 不建账号云端库（先本地 corpus）  
- 不一次爬全 GitHub（按 Skills → AI 验 skill → 增量队列）
