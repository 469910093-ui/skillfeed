# skill-feed 三个判定系统 · 独立模型 QA 审计报告

**审计类型**：首次审计（只读）
**审计对象**：行业分类器 `scene.py`、排序打分 `rank.py`、LLM 内容改写管线 `i18n.py`
**总体结论**：**三个系统均为「有重大发现」（Sound with Findings），其中分类器与排序引擎各存在 P0 级问题不建议在当前状态下继续放大用户量。**

---

## 0. 审计基线与可信度声明

### 0.1 代码读取时间点

| 文件 | 最后修改 | 我读取的时间 | 与产物一致性 |
|---|---|---|---|
| `scene.py` | 2026-09-03 15:46:32 | 16:46 | MD5 与 `~/.skill-feed/scene.py` **相同** |
| `rank.py` | 2026-09-03 11:29:25 | 16:46 | MD5 **相同** |
| `i18n.py` | 2026-09-03 16:34:00 | 16:46 | MD5 **相同** |
| `feed_pack.py` | 2026-09-03 11:29:25 | 16:48 | MD5 **相同** |
| `feedback.py` | 2026-09-03 11:29:25 | 16:48 | MD5 **相同** |
| `skillfeed.py` | 2026-09-03 16:40:20 | 16:47 | 只读了 i18n / retag 段 |
| `feed_dashboard.py` | 2026-09-03 16:43:45 | 16:52 | 只 grep 了 why / chip 渲染 |

仓库内副本与 `~/.skill-feed/` 运行时副本逐字节相同，因此**所有内存实验都作用于真正产出 `feed.json` 的那份代码**。

**审计后被并行改动的文件（时效性声明）**：审计结束时（17:18）复查发现

| 文件 | 我读取时 | 复查时 | 状态 |
|---|---|---|---|
| `rank.py` | 11:29:25 | **17:01:37** | 已被改；仓库版与运行时版 MD5 已不同 |
| `feed_pack.py` | 11:29:25 | **17:02:16** | 已被改 |
| `feedback.py` | 11:29:25 | **17:15:15** | 已被改 |
| `scene.py` / `i18n.py` | 15:46 / 16:34 | 未变 | 一致 |

同期仓库里新增了 `ranking.py`、`ranking_profile.py`、`impressions.py`、`server/ranking_service.py`、`docs/ranking-engine-design.md` —— 与你说明的「另一个 agent 正在重写排序引擎」一致。

**因此 §3（排序）的所有结论描述的是「产出当前 `feed.json` 的那一版 `rank.py`」，不是仓库 HEAD 的工作副本。** R-1 / R-2 / R-4 / R-5 / R-7 需要在重写落地后重新验证；但 R-1 的根因（`_norm_boost` 的 max 归一化）和 R-2 的根因（corpus 无 `rel_score`）是结构性的，除非显式处理，重写不会自动消除。§2（分类器）与 §4（LLM）的代码基线未变动，结论直接有效。

### 0.2 数据快照（重要）

审计过程中 `feed.json` 与 `cards.jsonl` **被并行 agent 改写了**：
`i18n.stats` 从 `cached=385/translated=2` 变成 `cached=387/translated=0`；`cards.jsonl` 从 1684 行涨到 2072 行。

因此我在 **2026-09-03 16:57:55** 把三个数据文件冻结到 `scripts/_tmp_qa_snap/`，本报告 §2 之后的**全部数字均出自该快照**：

- `feed.json`：`generated_at = 2026-09-03T08:49:31Z`，`items = 388`，`corpus = 378`
- `cards.jsonl`：2072 行
- `feedback.jsonl`：5 行

> 你交代的背景是「约 212 条」，实际快照是 **388 条入流 + 378 条 corpus 兜底**。差异会影响任何按比例外推的结论，建议核对一下是否有预期外的扩量。

### 0.3 复现性验证（前置门禁）

对全部 388 条重跑 `scene.apply_scene`，与 `feed.json` 里已存的 `scene / scene_l2 / scene_confidence / scene_why` 逐字段比对：

```
scene mismatch      : 0 (0.0%)
scene_l2 mismatch   : 0 (0.0%)
confidence mismatch : 0
why mismatch        : 0
```

**给定同一输入，分类器完全确定性可复现，复现 delta = 0%。** 这条通过，因此后续所有消融实验的结论是可信的。
但注意：这只证明「同输入同输出」，不证明「跨构建同输出」——见 **C-6**。

### 0.4 单测观察（按要求不修）

```
Ran 68 tests in 1.822s
FAILED (errors=1)
ERROR: test_gates.TestCorpusFeedback.test_corpus_ingest_and_feedback
  tests/test_gates.py:177  KeyError: 'opened_github'
    self.assertEqual(summary["by_action"]["opened_github"], 1)
```

`feedback.py` 正被并行修改，这很可能是中间态，仅记录不处理。

### 0.5 被否证的假设（如实记录）

审计要求里提示的两个方向，**数据不支持**，我不把它们写成发现：

| 假设 | 检验 | 结论 |
|---|---|---|
| 长文本天然命中更多 → 长条目置信度更高 | `r(hay 长度, scene_confidence) = -0.028`（n=388） | **否证**。`feed_pack.BODY_PREVIEW_MAX=700` 把 body 截平了，344/388 条的 haystack 长度都落在 1000–1499，长度方差被抹掉。代价是信息损失（见 C-5），但长度偏差本身当前不成立。 |
| `rel_score` 会突破 1.0 触发非单调断点 | 用 18 / 3787 / 11091 三档 `interest_toks` 模拟本机 catalog，`rel_score` 最大只到 **0.957**，`>1.0` 命中 **0/388** | **当前未触发**，因此 R-4 降级为潜伏缺陷而非在线故障。 |

---

## 1. 发现汇总

| # | 发现 | 严重度 | 系统 | 建议方向 |
|---|---|---|---|---|
| C-1 | 一级行业误判率 20%，二级徽标误判率 32.6%；UI 用「因为 · X · Y」把标签包装成理由 | **P0** | 分类器 | 把「理由」与「标签」解耦；低置信度不展示徽标 |
| C-2 | `SCENES_L2` 裸词地雷从未清理（`ui`/`bi`/`ux`/`api`/`库`/`mom`…），L1 修了 L2 没修 | **P0** | 分类器 | 引入词边界匹配；对 L2 做与 L1 同一轮清洗 |
| C-3 | `scene_confidence` 不是概率，ECE=0.117，conf=0.5 桶准确率仅 37.5% | P1 | 分类器 | 用标注集拟合映射，或改为离散档位并对低档弃权 |
| C-4 | `_PATH_DESIGN_KEYS` 按 `full_name` 匹配 → 整仓被强行归类 | P1 | 分类器 | 路径捷径限定到 `skill_path`/`dir_name`，且不得越过规则打分 |
| C-5 | 两遍分类看到的输入不同，frontmatter 快路径在第二遍是死代码，`retag_scenes` 声称的幂等不成立 | P1 | 分类器 | 单点分类，或让 `KEEP_KEYS` 覆盖 `_hay` 的全部输入 |
| C-6 | 循环依赖：23.5% 的一级标签由 LLM 文案决定，而同一输入有 169 个 skill 存在多份不同文案 | P1 | 分类器×LLM | 分类只吃确定性字段，或把 LLM 文案固化为版本化输入 |
| C-7 | 无字段权重、无词边界、命中数取胜；`r(词表长度占比, 条目占比)=0.837` | P2 | 分类器 | 加字段权重与 idf 类归一，让规模不等于胜出 |
| C-8 | `scene_why` 截断到 4 个（34 条隐藏 1–5 个命中）；展示的关键词 9.3% 是子串噪声 | P2 | 分类器 | why 记录全量命中并标注命中方式 |
| C-9 | 59/391 个关键词在 766 篇语料里 0 命中（死规则） | P2 | 分类器 | 规则表纳入覆盖率体检 |
| C-10 | 负向提及被当正向证据（`No database` → 命中 `database` → 判工程/云与部署） | P2 | 分类器 | 至少排除否定语境；长期看要换判别方式 |
| R-1 | 5 条反馈让 feed 头部 **top-10 重叠率 0%**，单条 skill 位移最大 +288 名 | **P0** | 排序 | 反馈生效需最小事件量与置信下界；boost 幅度对齐分数尺度 |
| R-2 | Explore/corpus 池 378 条**全部无 `rel_score`**，全池只有 4 个分值，310 条同键 | **P0** | 排序 | corpus 入池前补齐相关性；或明确按「无排序」呈现 |
| R-3 | live 池与 soft 池量纲不可比；df/idf 每批次在混合来源上重建 | P1 | 排序 | 固定 idf 语料或改用来源内归一后再合池 |
| R-4 | `score = _squash(base) if base > 1 else base` 非单调（1.0→1.0，1.0001→0.5000） | P1（潜伏） | 排序 | 统一用一个单调变换，全域生效 |
| R-5 | `rel_why` 打印未加权分量，6 个抽样里 3 个「最大项」标错 | P2 | 排序 | why 输出加权后的实际贡献 |
| R-6 | 服务中的 388 条里有 5 对完全重复（`graphify` 出自两个不同仓库） | P2 | 排序/打包 | 合池后再去重一次 |
| R-7 | 3.6% 条目落在完全相同排序键上，tie-break 退化为抓取顺序 | P2 | 排序 | 加确定性 tie-break（如 id 哈希） |
| I-1 | `_BANNED` 对部分 skill **不可满足**：`\.md\b` 让「生成 DESIGN.md」的 skill 永久失败并每轮重烧 token | **P0** | LLM | 禁词只针对「文档搬运」形态，不针对产物名 |
| I-2 | `content_hash` 不覆盖 prompt / model / 温度 / `BODY_LIMIT`；`model` 记录了但比对时不用 | **P0** | LLM | 指纹纳入「产出契约版本」；换 prompt/模型即整体失效 |
| I-3 | 同一 `(key, hash)` 下 **169 个 skill 有 ≥2 份不同文案**，服务的是文件最后一行 | **P0** | LLM | 一个键一条生效记录 + 显式版本号，禁止靠追加顺序决定 |
| I-4 | 服务中 387 条里 **93 条（24.0%）至少违反一条 prompt 硬约束**；`_valid_fields` 从不校验长度 | P1 | LLM | 把 prompt 里的硬约束搬进校验器；违规走重试而非放行 |
| I-5 | monorepo 缓存键退化：757/2072 行无 `skill_path`，`text-to-cad` 一个键下 45 行 / 7 个 hash | P1 | LLM | 一次性迁移旧行补键，去掉裸 `full_name` 回退 |
| I-6 | `cards.jsonl` 有 2 个写入方、3 种 schema、2 种时间戳格式 | P1 | LLM | 缓存文件单一写入方，跨进程走独立表 |
| I-7 | 失败降级质量差：兜底亮点是 Markdown 标题（`['Stitch Design Taste — Semantic…', 'Overview']`） | P2 | LLM | 失败态显式标注，不用标题冒充亮点 |
| I-8 | 数字断言不可靠：中文文案里 21 个量化断言有 **5 个（23.8%）** 原文不支持 | P1 | LLM | 禁止模型自造计数，或对数字做回查校验 |
| I-9 | `description == "../../SKILL.md"` 的坏条目通过了 `G_parse`（只查 `len>=10`） | P2 | 门禁 | 门禁增加坏值形态检查 |

---

## 2. 审计对象一 · 行业分类器 `scene.py`

### C-1【P0】误判率：一级 20%，二级徽标 32.6%

**抽样方法**：`scripts/_tmp_qa_06_sample.py`，简单随机抽样，`seed=20260903`，`n=100`，总体 `N=388`（快照 items）。
**标注口径**：对每条读 `one_liner_zh` + 英文原始 `description`，判定「被赋的行业是否是该 skill 自身交付物最自然的主类」。分类学本身没有对应桶时（如 PDF 工具、链上分账），弃权到 `other` 记**正确**；存在合适桶却弃权记**错误**。
**样本明细**留在 `scripts/_tmp_qa_06_sample.txt`（临时文件，见 §6）。

| 指标 | 点估计 | 95% CI（Wilson + 有限总体校正） | 外推到全量 |
|---|---|---|---|
| 一级行业误判率 | **20.0%**（20/100） | **[14.4%, 27.8%]** | ~78 / 388 张卡片行业错 |
| 二级徽标误判率（仅统计**展示了**徽标的卡片） | **32.6%**（29/89） | **[25.0%, 41.6%]** | ~118 / 362 个二级徽标错 |
| 该弃权而没弃权 / 该判却弃权 | 2/100 假弃权 | — | ~8 条本可归类却落进「其他」 |

**为什么这是 P0，而不只是「准确率一般」**：因为前端把标签**重写成了因果陈述**。

```python
# feed_dashboard.py:1551-1561
function friendlyWhy(it) {{
  const bits = [];
  const s1 = itemSceneLabel(it);
  const s2 = itemSceneL2Label(it);
  if (s1) bits.push(s1);
  if (s2) bits.push(s2);
  if (it.soft) bits.push(tr('leadLong'));
  else if (it.from_corpus) bits.push(tr('kb'));
  if (it.source) bits.push(sourceLabel(it.source));
  return bits.length ? (tr('because') + ' · ' + bits.join(' · ')) : '';
}}
```

`因为 · 内容创作 · 知识库` 里，`因为` 后面跟的**不是证据，是结论本身**。真正的证据字段 `scene_why` / `scene_confidence` 在整个 `feed_dashboard.py` 里**一次都没被渲染**（grep 无命中）。所以：

- 一个只靠 1 个关键词命中、准确率 37.5% 的判定，和一个 4 个关键词命中、准确率 100% 的判定，在界面上**完全无法区分**；
- 用户看到的是一句带因果连词的断言，而该断言有 1/5 概率是错的。

**代表性错例**（均来自随机样本）：

| skill | 实际做什么 | 被判 | 触发证据 |
|---|---|---|---|
| `full-output-enforcement` | 禁止 LLM 截断输出的 prompt 约束 | 设计与视觉 / Figma·UI | `path:taste`（仓库名 `Leonxlnx/taste-skill`）+ 裸词 `ui` |
| `total-recall` | 对话记忆摘要 | 工程开发 / 云与部署 | 命中 `database`——原文是 `No database. No vectors.` |
| `Autonomous Testing Agent` | 自动生成并修复测试 | 工程开发 / SDK·API | `开发`、`typescript`；应为 Bug与质量 / 测试验证 |
| `observability-and-instrumentation` | 注入日志/指标/链路追踪 | 数据与复盘 / BI指标 | `指标`、`数据` |
| `pr-to-video` | 把 PR 生成讲解视频 | 工程开发 / 重构架构 | `重构`、`refactor`、`开发` |
| `codex-review` | 代码审查 | 工程开发 / SDK·API | `开发`、`sdk`、**`aws`**（命中 `flaws`/`laws` 类词） |
| `remotion-upgrade` | 升级 npm 包 | 设计与视觉 | `remotion` 被登记为 design 关键词 |
| `dxf` | 生成 2D DXF 工程图纸 | Agent工具链 | 只靠 `hg:Skills` 兜底加分 |

**建议方向**：把「理由」和「标签」在数据契约上分开——理由必须携带可核验的命中证据与置信度；置信度低于阈值时二级徽标不渲染（一级可保留但需弱化视觉权重）。

---

### C-2【P0】`SCENES_L2` 的裸词地雷从未被清理

你列的历史问题**在 `RULES`（一级）里确实修好了**，我用 `git diff` 核实了这次修复的边界：

```
-        ("writing", "写作润色", ("写作","文案","润色","stop-slop","去ai味","copy","writing")),
+        ("writing", "写作润色", ("写作","文案","润色","stop-slop","去ai味","copywriting",)),
-        ("skill-mgmt", "Skill管理", ("skill-picker","skill-feed","skills","skill")),
+        ("skill-mgmt", "Skill管理", ("skill-picker","skill-feed","skill 管理","marketplace")),
```

**但同一次改动同时给 L2 新增了 `ux`，并且始终没有动 `ui`。** 一级注释里那段自我警示（`scene.py:210-212`、`219-220`、`256-258`）写得很清楚，却没有一条应用到 `SCENES_L2`。

**全量枚举**：391 个关键词条目（L1 187 / L2 190 / PATH 14），在 766 篇（items+corpus）语料上做词边界检验。ASCII 词才做边界检验——中文本来就靠子串匹配，`技术写作者` 命中 `写作` 是**合理的**，把它算污染会高估问题（这是我第一版度量的错误，已修正）。

**仍然在线的 ASCII 地雷（按噪声条数排序）**：

| 归属 | 关键词 | 命中篇数 | 真词命中 | 纯噪声 | 噪声率 | 实际吃到的词 |
|---|---|---|---|---|---|---|
| **L2** `design/figma` | **`ui`** | 245 (32.0%) | 32 | **213** | **87%** | `build`×131, `guidelines`×74, `building`×51, `requirements`×27, `requires`×26 |
| **L2** `data-review/bi` | **`bi`** | 142 (18.5%) | **0** | **142** | **100%** | `accessibility`×32, `capabilities`×20, `mobile`×17, `reliability`×17, `compatibility`×10 |
| **L2** `design/figma` | **`ux`** | 51 | 10 | 41 | 80% | `linux`×34, `nuxt`×17, `luxury`×4, `termux`×3, `tmux`×2 |
| L2 `quality/review` | `review` | 68 | 41 | 27 | 40% | `reviewing`, `reviews`, `preview`×10 |
| L1+L2 `quality` | `bug` | 33 | 14 | 19 | 58% | `debugging`×24, `bugs`×18 |
| L1+L2 `engineering` | `sql` | 28 | 12 | 16 | 57% | `sqlite`×18, `postgresql`×11, `mysql`×11 |
| **L2** `engineering/sdk` | `api` | 100 (13.1%) | 85 | 15 | 15% | `apis`×26, `openapi`×16, `fastapi`×7, **`scraping`×6** |
| L1+L2 `engineering` | `deploy` | 31 | 17 | 14 | 45% | `deployment`×31 |
| L1+L2 `engineering` | `refactor` | 20 | 10 | 10 | 50% | `refactoring`×12 |
| L1+L2 `engineering` | `postgres` | 11 | 4 | 7 | 64% | `postgresql`×11 |
| L1+L2 `quality` | `lint` | 10 | 4 | 6 | 60% | `accesslint`×8, `eslint`×2 |
| L2 `research/academic` | `citation` | 6 | 1 | 5 | 83% | `citations`×6 |
| **L1+L2** `data-review` | **`mom`** | 4 | **0** | **4** | **100%** | `moments`×2, `moment`×2 |
| L1+L2 `research` | `zettel` | 1 | **0** | 1 | **100%** | `zettelkasten`×3 |
| L2 `agent-tooling/skill-mgmt` | `marketplace` | 1 | **0** | 1 | **100%** | `marketplaces`×1 |
| L1 `engineering` | `aws` | 8 | 7 | 1 | 12% | `flaws`×2 |
| L1 `engineering` | `crawl` | 7 | 3 | 4 | 57% | `firecrawl`×39 |
| L1 `biz-vertical` | `flight` | 3 | 2 | 1 | 33% | `testflight` |
| L1 `collab` | `office` | 3 | 2 | 1 | 33% | `libreoffice`, `onlyoffice` |
| L2 `engineering/sdk` | `库` | 121 (15.8%) | — | — | — | 中文裸词，但覆盖 `数据库`/`仓库`/`组件库`/`知识库` 四个不同概念 |

**六个关键词的真词命中数为 0**：`bi`（142 篇！）、`mom`、`zettel`、`marketplace` —— 它们在这份语料上**从未作为真实单词出现过一次**，100% 的贡献都是误导。

**消融量化**（去掉所有「只以子串形式命中」的 ASCII 命中后重新取 argmax）：

```
一级：stable 323 (83.2%) | FLIP→其他行业 23 (5.9%) | FLIP→other 5 (1.3%)   => 7.2% 翻转
二级：stable 322 (83.0%) | FLIP→其他二级 23 (5.9%) | FLIP→无徽标 17 (4.4%) => 10.3% 翻转
```

按行业看，翻转集中在两处：`agent-tooling` 11/37（30%）、`quality` 8/33（24%）。
按二级看最差的桶是 **`design/figma` 12/44（27%）**——`ui` 一个词就撑起了 12 条错误徽标，包括 6 个 `remotion-*`、3 个 `hyperframes-*`。

**注意规模差**：自动消融只能解释 7.2%，而人工标注的真实误判是 20%。差额来自中文通用词（`开发` 命中 33.4% 语料、`数据` 16.8%、`架构`、`协作`）、路径捷径（C-4）和分类学缺口。**所以「把裸词清干净」是必要的，但远不够。**

**建议方向**：匹配层引入词边界（ASCII 用边界正则，中文可保持子串但要区分「独立词」与「更长复合词」两种命中强度）；并把 L1 那轮清洗对 `SCENES_L2` 完整重放一遍。

---

### C-3【P1】`scene_confidence` 是命中计数，不是概率

```python
# scene.py:399
    conf = min(0.95, 0.35 + 0.15 * top)
```

置信度是命中数的仿射函数，外加三个魔数：`0.9`（frontmatter）、`0.86`（路径捷径）、`0.2`（零命中）。它从未针对任何标注拟合过。

**取值分布**（388 条）：

| conf | 含义 | 条数 | 占比 |
|---|---|---|---|
| 0.2 | 零命中 | 6 | 1.5% |
| 0.5 | **恰好 1 个关键词命中** | 81 | 20.9% |
| 0.65 | 2 个命中 | 111 | 28.6% |
| 0.8 | 3 个命中 | 77 | 19.8% |
| 0.86 | 路径捷径 | 31 | 8.0% |
| 0.95 | ≥4 个命中（**封顶**） | 82 | 21.1% |

**校准表（reliability table，n=100 标注样本）**：

| conf | n | 判对 | 实际准确率 | gap = acc − conf | 95% CI |
|---|---|---|---|---|---|
| 0.2 | 4 | 2 | 50.0% | **+30.0%** | [15%, 85%] |
| **0.5** | 16 | 6 | **37.5%** | **−12.5%** | [18%, 61%] |
| **0.65** | 29 | 25 | **86.2%** | **+21.2%** | [69%, 95%] |
| 0.8 | 19 | 16 | 84.2% | +4.2% | [62%, 94%] |
| 0.86 | 11 | 10 | 90.9% | +4.9% | [62%, 98%] |
| 0.95 | 21 | 21 | 100.0% | +5.0% | [85%, 100%] |

**ECE（6 个原生分箱）= 0.117**，且**方向不一致**：0.5 档过度自信（−12.5pp），0.65 档严重欠自信（+21.2pp）。

**序关系是真的，数值是假的**：`点二列相关 r(conf, 判对) = 0.430`；`conf ≤ 0.50` 组准确率 40.0%（n=20），`conf ≥ 0.80` 组 92.2%（n=51）。也就是说这个分数**有用作阈值，不能当概率读**。

**最要紧的一格**：`conf ≤ 0.5` 覆盖 **87/388（22.4%）** 条目，该档实测准确率约 40%。**仅这一档就贡献约 52 张标错的卡片**，而它们在界面上和 0.95 档长得一模一样。

**建议方向**：先建标注集（下述 §5 的 G1），用它把命中数映射到经验准确率（保序回归/分箱平均都行）；同时把「1 个命中」这一档当作弃权候选而不是结论。

---

### C-4【P1】路径捷径按仓库名匹配，整仓被强行归类

```python
# scene.py:364-372
    path_hay = " ".join([
        item.get("skill_path") or "",
        item.get("dir_name") or "",
        item.get("name") or "",
        item.get("full_name") or "",
    ]).lower()
    for kw in _PATH_DESIGN_KEYS:
        if kw in path_hay:
            return "design", 0.86, f"path:{kw}"
```

这一段在**任何规则打分之前**直接 return，且 `path_hay` 含 `full_name`——**仓库名是仓库级的，一个名字就能俘获仓库里所有 skill**。

**实测**：31/388（8.0%）条目走了这条捷径。其中：

- `taste` 命中 `Leonxlnx/taste-skill` → **13 条**全部无条件判为「设计与视觉 @0.86」，其中 **9 条仅靠 `full_name` 命中**（`skill_path`/`name` 里没有 `taste`）。这 13 条里包括 `full-output-enforcement`（禁止 LLM 截断输出）、`image-to-code`、`stitch-design-taste`。
- `open-design` 命中 `nexu-io/open-design` → 4 条，包括 `chat-motion-overlay`（生成短视频对话浮层，更像内容创作）。

**为什么是问题**：0.86 这个数字比 4 个关键词命中的 0.95 只低一点，但它**没有任何内容证据**——它只知道仓库主人给仓库起了什么名字。`_PATH_DESIGN_KEYS` 里的 `taste` 尤其危险，因为它是个短通用词。

**建议方向**：路径捷径限定到 `skill_path` / `dir_name`（skill 自己的位置），不看 `full_name`；并且改为「加权重」而不是「直接 return」，让内容证据仍有机会覆盖它。

---

### C-5【P1】两遍分类看到的输入不同，「幂等」不成立

`retag_scenes` 的注释是：

```python
# skillfeed.py:120-134
def retag_scenes(feed: dict) -> None:
    """i18n 之后重跑行业分类。

    pack_feed 里第一次分类只看得到英文 SKILL.md 原文，噪音大；等 i18n 把中文
    一句话写进条目后再判一次，判定质量明显更好。apply_scene 是幂等的。
    """
```

**但两遍之间夹着 `normalize_item` 的字段裁剪。** `_hay` / `tag_scene` 用到 13 个输入，其中 4 个不在 `feed_pack.KEEP_KEYS` 里：

| `_hay`/`tag_scene` 输入 | 在 `KEEP_KEYS` | 服务条目中实际存在 |
|---|---|---|
| `name` / `skill_path` / `description` / `body_preview` / `hg_section` | ✅ | 388 / 378 / 388 / 378 / 35 |
| **`keywords`** | ❌ | **0/388** |
| **`repo_description`** | ❌ | **0/388** |
| **`dir_name`** | ❌ | **0/388** |
| **`frontmatter`** | ❌ | **0/388** |
| `one_liner_zh` / `one_liner_en` / `who_for_zh` / `highlights_zh` | ❌（i18n 之后才写入） | 387 |

加上 `feed_pack.BODY_PREVIEW_MAX = 700` 把正文截断，结论是：

- **第一遍**（`feed_pack.py:168`，normalize 之前）能看到 frontmatter / keywords / repo_description / dir_name + 未截断正文；
- **第二遍**（`retag_scenes`，normalize 之后）**看不到这四个字段**，正文只剩 700 字；
- 因此 `tag_scene` 里 conf=0.9 的 frontmatter 快路径（`scene.py:352-362`）和 `tag_scene_l2` 里 conf=0.9/0.88 的 frontmatter 路径（`scene.py:306-319`）**在第二遍是死代码**；
- 而第二遍的结果**无条件覆盖**第一遍。

**构造性证明**（纯内存，未写任何文件）：

```
输入：frontmatter={"category":"data","scene_l2":"bi"} + keywords="azure, billing, finops"
pass1  scene=data-review/bi  conf=0.9/0.9    why=frontmatter:category=data | frontmatter:scene_l2=bi
pass2  scene=data-review/bi  conf=0.5/0.55   why=rules:dashboard          | l2:dashboard
幂等？ L1 True   L2 True   conf False
```

这个例子里标签恰好没变，但**置信度从 0.9/0.9 掉到 0.5/0.55，理由从「作者自己声明的分类」退化成「命中了 dashboard 这个词」**。也就是说：作者在 frontmatter 里写明的权威分类信息，在最终产物里被一个关键词猜测替换掉了。`scene_why`/`scene_confidence` 本身也不在 `KEEP_KEYS` 里，所以 **`feed.json` 里的置信度 100% 来自信息更少的第二遍**。

**建议方向**：要么只分类一次（在字段最全的时刻），要么让 `KEEP_KEYS` 覆盖 `_hay` 的全部输入；无论哪种，第二遍不应该在证据更弱时覆盖更强的结论。

---

### C-6【P1】循环依赖：行业标签是 LLM 采样结果的函数

`_hay` 吃 i18n 产出（`scene.py:281-287`），而 `retag_scenes` 跑在 i18n 之后。**把这 4 个 LLM 字段从 `_hay` 里摘掉再重判**：

```
一级标签由 LLM 文案决定的条目 : 91/388 (23.5%)
二级标签由 LLM 文案决定的条目 : 130/388 (33.5%)
置信度由 LLM 文案改变的条目   : 205/388 (52.8%)
```

典型（左边是「没有 LLM 文案时的判定」，右边是「实际服务的判定」）：

```
doc-coauthoring      agent-tooling → content     |  prompt        → writing
music-generation     agent-tooling → content     |  prompt        → short-video
skill-creator        agent-tooling → data-review |  prompt        → bi
find-skills          agent-tooling → engineering |  prompt        → infra
competitor-monitor   other         → content     |  (无)          → writing
```

单看这些，i18n 确实**改善**了判定（中文一句话比 `Use when...` 干净）。问题在于它和 **I-3** 叠加：

> **169 个 skill 在 `content_hash` 完全相同的情况下，缓存里存着 ≥2 份内容不同的文案**，而实际生效的那份只是 `cards.jsonl` 里最后追加的一行。

两者相乘的结论是：**23.5% 的条目的行业标签，取决于哪一次 LLM 采样恰好最后落盘。** 这不是「可能漂移」，这是构造上就不可复现。§0.3 的「复现 delta = 0%」只覆盖同输入同输出，跨构建这条不成立。

**建议方向**：分类器只吃确定性字段；如果确实要用 LLM 文案提升质量，就必须先让那份文案本身可复现（一个键一条生效记录 + 版本号），否则等于把随机性接进了标签。

---

### C-7 / C-8 / C-9 / C-10【P2】架构层缺陷

**C-7 词表长度直接兑换成占比。** 无字段权重、无词边界、`best = max(scores)` 取原始命中数：

| 行业 | 关键词数 | 词表占比 | 判到的条目 | 条目占比 |
|---|---|---|---|---|
| engineering | 37 | 19.8% | 132 | **34.0%** |
| design | 34 | 18.2% | 68 | 17.5% |
| content | 27 | 14.4% | 40 | 10.3% |
| data-review | 22 | 11.8% | 26 | 6.7% |
| collab | 16 | 8.6% | 26 | 6.7% |
| agent-tooling | 16 | 8.6% | 37 | 9.5% |
| research | 13 | 7.0% | 16 | 4.1% |
| biz-vertical | 12 | 6.4% | 4 | 1.0% |
| quality | 10 | 5.3% | 33 | 8.5% |

**`r(词表长度占比, 条目占比) = 0.837`（n=9）**。想让某个行业多收条目，只要往它的列表里塞词——这不是判别力，是配额。历史上「71% 落进 Agent工具链」是同一个机制的极端形态（当时靠 `skill` 这个 100% 覆盖的词），现在换成了 `engineering` 靠 `开发`（命中 33.4% 语料）领跑。**这个缺陷没有被修复，只是换了受益方。**

另外，一级里做了 `agent-tooling` 平局让位（`scene.py:395-397`），但对 `engineering` 没有对应约束，而 `engineering` 才是当前的吸收态。

**C-8 `scene_why` 不完整也不干净。**
- 截断到 4 个（`scene.py:400`）：34 条隐藏了 1–5 个额外命中（`hidden=1: 15, =2: 13, =3: 3, =4: 2, =5: 1`）。
- 862 个展示出来的关键词里 **80 个（9.3%）是 ASCII 子串噪声**；73 条（18.8%）的 why 里至少有一个噪声词；**4 条的 why 100% 是噪声**。
- 缓解因素：why 目前**不面向用户**（前端未渲染），所以这是可观测性问题而非误导用户问题。但它同时意味着**开发者调试时看到的证据是不完整且被污染的**，这会让 C-2 类问题更难被发现。

**C-9 死规则。** 391 个关键词里 **59 个在 766 篇语料上 0 命中**，包括 `周报`、`gmv`、`拉数`、`活动复盘`、`电商`、`淘宝`、`天猫`、`unittest`、`read-anything`、`skill-picker`、`skill-feed`、`轮椅`、`辅具`，以及 4 个 `PATH` 键（`shadcn`、`ui-ux`、`ui-design`、`product-design`）。它们不造成错误，但让规则表看起来比实际能力大得多，且掩盖了 `biz-vertical` 只有 4 条（1.0%）这一事实——这个行业实质上处于未覆盖状态。

**C-10 否定语境被当正向证据。** 子串匹配读不出否定：

```
total-recall  描述："No database. No vectors. No manual saves."
              → 命中 engineering 的 `database` → 判「工程开发 / 云与部署」
              实际是对话记忆摘要工具（应为 研究与知识/笔记知识库）
```

同类还有 `没有广告`/`无广告` 命中 `广告` → `biz-vertical/marketing`（8 篇里 2 篇是 `无广告`）。

---

## 3. 审计对象二 · 排序打分 `rank.py`

> 按你的交代，这里只谈方法论，不提「缺 CTR / Wilson / 多样性」这类功能缺失。

### R-1【P0】5 条反馈重排整个 feed 头部

`feedback.jsonl` 只有 **5 条**事件，其中 **4 条指向同一个仓库**：

```
2026-07-27T10:20:59  opened_github  hardikpandya/stop-slop   scene=content
2026-07-27T10:24:18  useful         hardikpandya/stop-slop   scene=content
2026-07-27T10:44:20  opened_github  anthropics/skills        scene=agent-tooling  l2=skill-mgmt
2026-07-27T10:56:11  useful         hardikpandya/stop-slop   scene=content  l2=writing
2026-07-27T10:56:13  useful         hardikpandya/stop-slop   scene=content  l2=writing
```

产出的画像：

```json
{"scene_boost": {"content": 0.22, "agent-tooling": 0.0367},
 "scene_l2_boost": {"skill-mgmt": 0.054, "writing": 0.18},
 "repo_boost": {"hardikpandya/stop-slop": 0.3, "anthropics/skills": 0.05},
 "events": 5}
```

**根因是 max 归一化**：

```python
# rank.py:206-211
    def _norm_boost(d: dict[str, float], cap: float = 0.25) -> dict[str, float]:
        if not d:
            return {}
        m = max(d.values()) or 1.0
        return {k: round(cap * (v / m), 4) for k, v in d.items()}
```

分母是**该维度内的最大值**，与绝对事件量无关。所以「点击最多的那个」**永远拿满档**——哪怕它只被点了 1 次。`content` 拿到满额 0.22 的依据，是 3 次点击。

**影响半径**：

```
受到反馈加权的条目            : 90/388 (23.2%)
  scene_boost content  +0.2200 → 40 条 (10.3%)
  l2_boost    writing  +0.1800 →  8 条 (2.1%)
  repo_boost  stop-slop +0.3000 →  1 条
personal_score 全局 stdev = 0.1891 ，IQR = 0.1783
单条可获得的最大反馈加成 = 0.22 + 0.18 + 0.30 = 0.70 ≈ 3.7 σ
```

**反事实重排**（live 池，有 affinity vs 无 affinity）：

```
top-5  重叠 = 0/5   (0%)
top-10 重叠 = 0/10  (0%)
top-20 重叠 = 2/20  (10%)
top-50 重叠 = 24/50 (48%)

位移最大的条目：
  seeding-copywriting  +288 名     title-writing   +231 名
  competitor-monitor   +251 名     image-editing   +231 名
  cover-design         +230 名     script-writing  +229 名
```

**5 条反馈把 feed 的前 10 名换了个彻底。** 一个加成上限 0.70 的量级，作用在 σ=0.19 的分布上，等于加成完全支配了相关性信号。同时 `stop-slop` 自己拿到 `rel 0.71 + 0.22 + 0.18 + 0.30 + 0.08 + 0.04 = 1.5376`，是全场最高分——它成了榜首，仅因为被点过 3 次。

**建议方向**：反馈生效应有最小事件量门槛与置信下界（少量样本时收缩到 0）；boost 幅度要相对于当前分数分布的尺度来定，而不是相对于「同维度最大值」；`repo_boost` 尤其应该考虑它只影响 1 条却拿最大 cap 的合理性。

### R-2【P0】Explore 池完全没有相关性信号

```
corpus 行数            : 378
  有 rel_score         : 0
  有 personal_score    : 378
personal_score         : min=0.0300 max=0.4300 mean=0.0594
不同取值个数           : 4
落在并列组里的条目     : 378/378 (100%)
  key=(0.03,   0.0, 0) → 310 行共享
  key=(0.25,   0.0, 0) →  39 行共享
  key=(0.0667, 0.0, 0) →  25 行共享
  key=(0.43,   0.0, 0) →   4 行共享
personal_why 取值：310× "rel:0.00 · src:+0.04"
```

`personalize_score` 取 `base = float(item.get("rel_score") or 0)`（`rank.py:257`），corpus 行没有 `rel_score` → **base 全为 0**。于是 378 条兜底池的分数只由来源常数和反馈决定，**整池只有 4 个不同分值，310 条共享同一个完整排序键**。`rerank` 的 `out.sort` 是稳定排序（`rank.py:326-330`），所以这 310 条的实际先后**完全等于抓取顺序**。

无限滑动补货的这 378 条，对用户而言是**无序**的，但界面呈现方式和有序的 live 池没有任何区别。

**建议方向**：corpus 入池前把相关性补齐（哪怕是离线一次性算好存下来），或者在产品上明确把这一段呈现为「随机/浏览」而非「推荐」。

### R-3【P1】量纲不可比

三处不可比叠在一起：

1. **live vs soft**：live 池 `rel_score ∈ [0.3555, 0.9417]`（n=374，均值 0.7045）；soft 池 14 条无 `rel_score` → base=0。它们被分别 `rerank` 后直接 `live + soft` 拼接（`feed_pack.py:169-178`），所以顺序上没串味——但**分数被写进同一个字段 `personal_score` 并对外暴露**，跨池比较是无意义的。例如 `last30days`（57k star）拿到 `rel:0.00 · pref:agent-tooling:+0.04 · pref2:skill-mgmt:+0.05 · stars:0.10 · src:+0.05 = 0.2258`，和一个真正高相关条目的 0.9 放在同一标尺上。
2. **df/idf 每批次重建**：`gates.py:59-68` 用**本轮候选**构建 `df`，`n = len(候选)`。同一个 skill 在不同批次（不同来源组合、不同候选数）会拿到不同的 idf，因此 **`rel_score` 跨构建不可比**，也不能做时间序列监控。
3. **来源均值差异**：`rel_score` 按来源 `github-search 0.7526 / xiaohongshu 0.7074 / catalog 0.7036 / hellogithub 0.6469`；再叠加固定的来源常数（`hellogithub +0.04 / trending +0.05 / github-search +0.02 / corpus −0.02`，`rank.py:293-299`）。这些常数是手工的，没有任何标定依据。

**建议方向**：idf 语料固定下来（离线全量语料），或者放弃跨来源直接比分，改成来源内归一后再合池。

### R-4【P1，潜伏】非单调变换

```python
# rank.py:257-260
    base = float(item.get("rel_score") or 0)
    # rel 软归一，保证反馈/意图增量可见
    score = _squash(base) if base > 1 else base
```

| base | 变换后 |
|---|---|
| 0.99 | 0.9900 |
| **1.0000** | **1.0000** |
| **1.0001** | **0.5000** ← 断崖 |
| 1.5 | 0.6000 |

**相关性更高的候选会拿到更低的个性化分。** 我做了尽职调查确认它当前是否在线：

```
观测 rel_score : n=374  min=0.3555  max=0.9417
rel_score > 1.0 的条目 : 0/388
模拟本机 catalog（|toks| = 18 / 3787 / 11091）：max = 0.747 / 0.957 / 0.946，rel>1.0 命中 0/388
```

**所以这是潜伏缺陷，不是在线故障**，我据此把它定为 P1 而非 P0。但两条证据说明作者预期它会被触发：`relevance_score` 结尾有 `min(score, 1.5)`（`rank.py:148`），而理论上限是 `0.45+0.40+0.15+0.08+0.12 = 1.20`。任何一次调权重或加成上限，都会把这个分支激活。

**建议方向**：全域用同一个单调变换（要么都 squash，要么都不 squash），不要按区间分叉。

### R-5 / R-6 / R-7【P2】

**R-5 `rel_why` 打印的不是贡献。** 显示的是 squash 后的原始分量，实际权重是 `0.45 / 0.40 / 0.15`（`rank.py:130`）：

```
stop-slop           why=name:0.39 · desc:0.82 · kw:0.86 · has:SKILL.md
   显示最大项 = kw    实际最大项 = desc
   真实贡献 = {name: 0.176, desc: 0.328, kw: 0.129}
```

6 个抽样里 **3 个的「看起来最大项」是错的**（`stop-slop`、`research`、`writing-guidelines`）。`rank_why` 又把 `rel_why`（分量）和 `personal_why`（加法项）拼进同一个字符串，两套量纲混在一句里。缓解因素同 C-8：前端未渲染，属于可观测性问题。`personal_why` 本身的加法是自洽的（400 条里只有 8 条超出 0.011 容差，来自 `.2f` 打印的舍入累积）。

**R-6 重复条目。** 388 条里有 **5 对 `id` 完全相同的重复**（`archify`、`ponytail`、`graphify`×2 组、`academic-research-skills`），`full_name+name` 维度是 6 对（多一个 `cate-cli`）。注意 `graphify` 是**两个不同仓库**（`safishamsi/graphify` 和 `Graphify-Labs/graphify`）各自重复。此外 `web-design-guidelines` 从 3 个不同仓库各出现一次，内容近似——同名近重不在去重范围，但对用户是同一种噪声。

**R-7 并列退化。** 388 条里有 14 条（3.6%）落在完全相同的 `(personal_score, rel_score, stars)` 上，最大并列组 4 条。稳定排序把 tie-break 交给输入顺序 = 抓取顺序，跨构建不稳定。live 池这个比例还小，corpus 池是 100%（见 R-2）。`feed.json` 里存储顺序对 `personal_score` 单调性违规 0 次，说明文件是两段有序拼接，本身没问题。

---

## 4. 审计对象三 · LLM 内容改写管线 `i18n.py`

### I-1【P0】`_BANNED` 对部分 skill 不可满足，导致永久失败 + 永久烧钱

```python
# i18n.py:161-165
_BANNED = re.compile(
    r"(https?://|references/|\.md\b|Requires\b|Optional extras|pip install|npm install)",
    re.I,
)
```

`failed=1` 那一条我查到了：

```
FAILED ITEM: stitch-design-taste  (Leonxlnx/taste-skill :: skills/stitch-skill/SKILL.md)
  description: "Semantic Design System Skill for Google Stitch. Generates agent-friendly
                DESIGN.md files that enforce premium, anti-generic UI standards …"
  原文里模型必须描述的 .md 产物: ['DESIGN.md']
  在缓存里? False  （裸 full_name 命中? True）
```

**这个 skill 的核心交付物就是 `DESIGN.md` 文件。** 一句忠实的中文摘要必然要提到它，而 `_valid_fields` 见到 `.md` 就判整条失败（`i18n.py:174` / `:182-184`）。这不是偶发网络失败，是**逻辑上不可满足的约束**：模型每次都会（正确地）提到 `DESIGN.md`，然后每次都被丢掉。后果是每轮构建都为它付一次 LLM 调用并且必定失败。

**同一陷阱边缘还有 10 条**：`description` 里已经点名 `.md` 产物的条目（`repo-task-proof-loop`→`.agent/t…`、`web-design`→`DESIGN.md`、`hyperframes-core`、`domain-modeling`、`caveman-learn`、`constraint-driven-development`、`azure-deploy`、`hyperframes-creative`、`xhs-note-creator`）。它们目前 `i18n_ready=True`，只是因为模型这次恰好没写出文件名——**这是运气，不是保证**。

`Requires\b`（大小写不敏感）同理会毙掉任何用到 `requires` 这个普通动词的英文句子；实测服务中的英文字段里 `requires` 出现 0 次，正是因为校验器把它们都丢掉了。

**建议方向**：禁词的原意是「别把安装说明当卖点」，但实现方式是「见到文件名就杀」。这两件事需要拆开——禁的应该是「安装/依赖说明这种句式」，不是「产物的名字」。

### I-2【P0】缓存指纹漏掉全部产出契约

```python
# i18n.py:90-99
def content_hash(item: dict) -> str:
    """内容指纹：描述或正文变了才需要重译。"""
    raw = "\n".join(
        [
            str(item.get("name") or ""),
            str(item.get("description") or ""),
            str(item.get("body_preview") or "")[:BODY_LIMIT],
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
```

**会改变输出、但不在指纹里的输入**：

- `SYSTEM_PROMPT` / `USER_TEMPLATE` 全文（包括那些 40/22/18/14 字数约束）
- `model`（`qwen-plus` → 别的模型）
- `temperature = 0.2`
- `BODY_LIMIT = 1800`
- `_call_model` 内部的 `description[:600]` 截断长度
- `_valid_fields` / `_BANNED` 的规则版本

`model` 更刺眼：它**被逐行记录了**，但命中判定里根本不看它：

```python
# i18n.py:291-299
        if hit and not force and _valid_fields(hit.get("fields") or {}):
            if hit.get("locked") or hit.get("hash") == h:
                attach(it, hit["fields"])
```

命中条件只有 `locked` 或 `hash` 相等。**换模型不会触发任何重译**，2072 行缓存全是 `qwen-plus`，一旦换成别的模型，所有旧文案会原封不动继续服务，而 `feed['i18n']['model']` 会诚实地写上新模型名——元数据与实际产出脱钩。

改 prompt 同理：所有约束都写在 prompt 里，改了约束但 hash 不变，缓存不失效，等于新约束对 99% 的存量条目无效。

**建议方向**：指纹应该覆盖「产出契约」整体——输入内容 + prompt 版本 + 模型 + 解码参数 + 校验规则版本。任一项变化即整体失效。

### I-3【P0】同一输入存着多份不同文案，生效的那份取决于追加顺序

```python
# i18n.py:114-133
def load_cache(data_dir: Path) -> dict[str, dict]:
    """读缓存。同一键后写的覆盖先写的。"""
```

实测：

```
cards.jsonl 行数     : 2072
不同 cache key       : 432
行/键 放大倍数       : 4.80x
(key, hash) 组 >1 行 : 565
  其中输出内容不同   : 169   ← 同一 hash、同一键，文案不一样
  其中输出完全一致   : 396
```

**169 个 skill 有 ≥2 份对外文案，服务哪一份只看谁最后落盘。** 实例：

```
KEY hardikpandya/stop-slop   hash=f8f5ff333f233de2   versions=2
  06:21:51  一键删掉AI腔调，让文字回归真实人类表达。
            ['删除填充短语和冗余副词', '打破套路化句式与结构',  '强制使用主动语态和具体主语']
  06:30:31  一键删掉AI腔调，让文字更像真人写的。
            ['删除空洞套话和冗余副词', '打破刻板句式与虚假节奏', '强制使用主动语态和具体主语']
```

这两份质量都不错，所以看起来无害。但结合 **C-6**（23.5% 的行业标签由这段文案决定）和 **I-8**（数字断言会自相矛盾），后果就不只是文案抖动了。

`temperature=0.2` 不是 0，`response_format` 也不保证逐 token 稳定——所以「同输入多输出」是预期行为。真正的缺陷是**系统把它当成了幂等函数，用「最后一行赢」这种隐式规则决定对外内容**。

**建议方向**：一个键只应有一条生效记录（追加式日志可以留作历史，但生效那条要显式指定），并把生效记录的版本号写进 `feed.json`，让「这次看板显示的是哪一版文案」可审计。

### I-4【P1】约束遵守率：服务中 24.0% 的条目至少违反一条硬约束

prompt 定了硬约束（`i18n.py:59-75`），但 `_valid_fields`（`i18n.py:168-186`）**只查存在性、类型、禁词**，从不查长度，还把「恰好 3 条」放宽成 `len(items) >= 2` 然后 `[:3]`。

**服务中的 387 条 `i18n_ready` 条目**：

| 违规项 | 条数 | 占比 |
|---|---|---|
| `highlights_zh` 单条 > 18 汉字 | 88 | 22.7% |
| `highlights_en` 单条 > 10 词 | 46 | 11.9% |
| `who_for_zh` > 14 汉字 | 14 | 3.6% |
| `highlights_en` 条数 = 2（≠3） | 7 | 1.8% |
| `highlights_zh` 条数 = 2（≠3） | 5 | 1.3% |
| `who_for_en` > 8 词 | 4 | 1.0% |
| **zh/en 条数不匹配（破坏一一对应）** | **2** | 0.5% |
| `one_liner_en` > 22 词 | 1 | 0.3% |
| **至少违反一条** | **93** | **24.0%** |

缓存全量（2072 行）的违规率更高：`highlights_zh > 18 汉字` **24.7%**、`highlights_en > 10 词` 11.9%、`who_for_zh > 14 汉字` 4.0%。

最超标的例子：

```
[26 汉字] 一键解析飞书多维表格链接，自动识别表/视图/记录等目标实体
[26 汉字] 输出持仓+宏观双维度综合判断，含可持续收益与激励收益拆分
[15 词  ] Understands natural queries like 'how do I X' or 'is there a skill for X'
[43 汉字] 自动扫描全网，实时发现正在使用、集成或推广你产品的开发者，并生成本周优先联系的高价值线索清单。
```

**「zh/en 条数不匹配」是最该关注的一条**：prompt 明确要求「中英一一对应同义」，而校验器允许 zh 3 条 / en 2 条通过。前端切语言时，用户会看到两种语言下**能力点数量不同**——这直接破坏了双语层的核心承诺。

**建议方向**：prompt 里写成硬约束的东西必须在校验器里同样是硬约束；违规应触发重试（带上违规反馈），而不是静默放行。

### I-5【P1】monorepo 缓存键退化，导致缓存震荡

```python
# i18n.py:102-111
def cache_key(item: dict) -> str:
    """缓存键 = full_name + skill_path。
    monorepo 一个仓库能展开出十几条 skill，它们 full_name 相同 …
    """
```

意图对，但存量数据没迁移：**2072 行里 757 行没有 `skill_path`**，`cache_key` 对它们塌回裸 `full_name`。

```
KEY 'earthtojake/text-to-cad'  rows=45
  不同 content_hash: 7   {d4ec…:8, 6871…:8, e9a5…:7, 84a8…:8, 4d50…:6, 5460…:6, 5176…:2}
  这些行的 skill_path: {'<EMPTY>': 45}
KEY 'obra/superpowers'         rows=43   不同 hash: 11   skill_path 全空
KEY 'Leonxlnx/taste-skill'     rows=42   不同 hash: 10   skill_path 全空
```

那 7 个 hash 其实是**同一仓库里的 7 个不同 skill**（G-code、STEP/CAD、DXF…）。`load_cache` 只保留最后一行，`enrich_items` 在 keyed 未命中时回退到 `cache.get(fn)`（`i18n.py:288-290`），拿到的那一行 hash 最多匹配 7 个兄弟里的 1 个，**剩下 6 个每轮构建都重译**。这就是 4.80x 放大的机制。

hash 比对本身**保护了正确性**（不会把兄弟的译文错贴过去，这点是对的），但代价是持续的 token 消耗。仅看带 `skill_path` 的行，放大倍数仍是 3.49x，说明还有第二重原因；同时 30/432 个键被观测到有多个 `content_hash`。

**注**：`_valid_fields` 拒绝自己缓存导致永久未命中的假设，我检验后**否证**了——2072 行里 0 行未通过自身校验器。这条不是原因。

### I-6【P1】`cards.jsonl` 有多个写入方（并行改动中）

```
1007 行  keys=[at, fields, full_name, hash, locked, model, record_id, skill_path, status]
 727 行  keys=[at, fields, full_name, hash, model]
 338 行  keys=[at, fields, full_name, hash, model, skill_path]
时间戳格式: {ISO-T: 1065, SPACE: 1007}
```

那 1007 行带 `record_id` / `status` / `locked`，时间戳用空格分隔而非 ISO `T`——来自另一个写入方（看起来是并行 agent 的多维表格同步链路）。**这是在途改动，我只做记录。**

但要指出结构性风险：`load_cache` 是**按 `cache_key` 最后一行赢**。这意味着第二个写入方**可以静默改变对外文案**，只要它追加的行 hash 恰好匹配。`locked` 字段（3 行为 True）会让该条**永久冻结、上游改了也不重译**（`i18n.py:294-298`）——这是有意设计，但需要有人能审计「哪些条被锁了、锁的是哪一版」。

**建议方向**：缓存文件保持单一写入方；跨进程的人工验收状态放独立存储，通过显式引用生效，而不是往同一个 append-only 文件里插行。

### I-7【P2】失败降级质量差

`stitch-design-taste` 失败后，前端拿到的兜底是：

```
one_liner  = "Semantic Design System Skill for Google Stitch. Generates agent-friendly DESIGN.md files t…"
problem    = 同上（截断）
highlights = ['Stitch Design Taste — Semantic Design Sy', 'Overview']
```

`highlights` 是 `highlights.extract_highlights` 从 Markdown 抽出来的，结果是**把一级标题和「Overview」当成能力点**。前端没有任何「这条未经改写」的标识（`i18n_ready` 字段前端未使用），所以用户看到的是一条**内容为噪声、外观与正常卡片完全一致**的卡片。

**建议方向**：失败态显式标注（哪怕只降级为「打开 GitHub 查看」），不要用标题冒充亮点。

### I-8【P1】数字断言不可靠：23.8% 的量化说法原文不支持

**方法**：从服务中的 `one_liner_zh + highlights_zh` 提取所有 `<数字><量词>`（种/个/张/条/层/步/套/大/多/款/类）形式的断言，回查该数字串是否出现在模型唯一见过的输入（`name + description + body_preview`）里。原文里没有这个数字 = 无依据断言。

```
服务文案中的量化断言 : 21
原文不支持的          : 5 (23.8%)
携带无依据断言的条目  : 5/387
```

| skill | 无依据断言 | 文案 |
|---|---|---|
| `gcode` | `7种` | 支持STL/OBJ/GLB等**7种**主流3D格式转G代码 |
| `cad-viewer` | `12种` | 支持**12种**主流CAD与机器人描述文件格式 |
| `ppt-generation` | `5种` | 支持商务/学术/极简等**5种**预设风格 |
| `seo-image-gen` | `7 类` | 自动生成 OG 图、博客头图等 **7 类** SEO 图片 |
| `last30days` | `7大` | 聚合**7大**平台最新原生内容，不依赖二手报道 |

**更硬的证据 —— 同一输入自相矛盾**。`(key, hash)` 完全相同（即 prompt 逐字节相同）的多份采样里，有 **3 组的数字断言互相冲突**：

```
earthtojake/text-to-cad  hash=d4ec9e721e855a2c  versions=8
  06:22:47  claims=['7种']  从3D模型文件生成、检查并验证打印机无关的G-code
  06:24:49  claims=['6种']  从3D模型文件直接生成、检查并验证打印机无关的G-code
  06:27:57  claims=['7种']
  07:36:39  claims=['6种']   ← 同一份原文，一会 6 种一会 7 种
```

```
vercel-labs/agent-skills  hash=9395a97e938c7abc  versions=4
  07:23:26  claims=['70 条']    07:41:49  claims=（无）
```

同一份原文既产出「6 种」又产出「7 种」，**至少有一个是编的**；而用户看到哪个，只取决于哪一行最后落盘。

**结论**：模型对**定性描述**基本忠实——我在 100 条随机样本里逐条比对 `one_liner_zh` 与英文原文，没有发现「说了原文没有的功能」这类功能性幻觉，中英两版在语义上也基本一致（除 I-4 里那 2 条条数不匹配）。**幻觉集中在具体计数上**，这恰恰是用户最容易当真、也最容易被打脸的部分（用户点进 GitHub 一数只有 5 种格式）。

**建议方向**：prompt 层面禁止模型自造计数，或在校验层对数字做原文回查（这是个便宜的确定性检查）。

### I-9【P2】坏 description 通过了门禁

```
xhs-note-creator   description = "../../SKILL.md"
```

`G_parse` 只查 `len(name) >= 1 and len(desc) >= 10`（`gates.py:113-118`），`"../../SKILL.md"` 长度 14 就过了。这条最终 `i18n_ready=True`（模型靠 `body_preview` 产出了合理文案），所以没造成可见故障——但它说明门禁对**坏值形态**没有防御。

---

## 5. 三个系统里哪个对用户体验伤害最大

**结论：行业分类器 `scene.py` 的伤害最大。** 排序引擎的单个缺陷更"急"，但分类器的伤害更"深"。推理依据如下：

### 5.1 按「错误可见性 × 覆盖面 × 用户可纠正性」三轴比较

| 维度 | 分类器 | 排序 | LLM 改写 |
|---|---|---|---|
| 错误率 | L1 **20%**（CI 14.4–27.8%），L2 徽标 **32.6%** | 头部 top-10 与无个性化重叠 0% | 硬约束违规 24.0%；数字断言无依据 23.8%（但只 5/387 条带数字） |
| 错误是否对用户可见 | **是**，直接渲染成「因为 · X · Y」 | 部分：用户不知道"本该是什么顺序" | 是，但多为轻微（长度超标、条数少一条） |
| 覆盖面 | 388/388 条，每条两个徽标 | 388 条顺序 + 378 条 Explore 无序 | 387/388 条文案 |
| 用户能否自行纠正 | **不能**——用户是靠行业筛选来找 skill 的，标签错了他根本到不了那张卡 | 能——可以往下滑、可以搜索 | 能——点进 GitHub 看原文 |
| 错误是否会自我放大 | **会**（见 5.2） | 会（反馈闭环）但需要用户先给反馈 | 不会 |

### 5.2 决定性理由：分类器的错误会污染另外两个系统

这不是三个并列的系统，是一条有向链：

```
scene.py ──► rank.py     ：scene_boost / scene_l2_boost 都按 scene 聚合。
                           分类错了，反馈信号就归错了行业。
                           实测：content 的 +0.22 加到 40 条上——只要这 40 条里
                           有 20% 是误判进来的，反馈就在给错误的行业加权。
scene.py ──► 用户筛选     ：feed_dashboard 的行业筛选 / Stories 圆环 / "关注行业"
                           全部以 scene 为键。标签错 = 该 skill 从筛选结果里消失，
                           且用户没有任何途径发现它不见了（这是沉默失败）。
i18n.py  ──► scene.py    ：23.5% 的一级标签由 LLM 文案决定（C-6），
                           而 169 个 skill 有多份文案（I-3）→ 标签跨构建漂移。
```

第二条是关键：**排序错误是「好东西排后面了」，用户往下滑还能找到；分类错误是「好东西被归到别的抽屉了」，用户在自己的抽屉里翻一辈子也翻不到。** 而这个产品的定位恰恰是"本机没有合适 skill 时按意图浏览远程线索"——按意图浏览的第一层就是行业筛选。

第三条让分类错误变得**不可调试**：同一次构建里可复现（delta 0%），跨构建会漂移。运营发现某条归错了，重跑一次可能就变了，也可能没变——这种间歇性错误的排查成本远高于稳定错误。

### 5.3 为什么排序的 P0 排第二，而不是第一

R-1（5 条反馈重排头部）的绝对严重度很高，但有三个减轻因素：

1. **规模小到不真实**：`feedback.jsonl` 只有 5 条，且都是 7 月 27 日同一小时内、极可能是开发者自测。真实用户量下 max 归一化的极端性会稀释（但不会消失——`_norm_boost` 的结构性缺陷在任何量级都成立）。
2. **有人正在重写**：你说明了另一个 agent 在加 CTR、Wilson 下界、多样性配额。这些改动天然会覆盖 R-1 的根因。
3. **可逆**：清空 `feedback.jsonl` 就能立刻回到无个性化状态；分类错误没有这种开关。

R-2（Explore 池 378 条无序）覆盖面更大且当前就在线，但它影响的是"补货池"而非首屏，且用户对无限滑动内容的顺序期待本来就低。

### 5.4 LLM 管线排第三

I-1/I-2/I-3 都是 P0，但它们的伤害形态是**成本与可审计性**，不是用户体验：

- I-1 只影响 1 条（外加 10 条潜在），用户侧表现是一张兜底卡片；
- I-2/I-3 的用户可见后果是"文案偶尔换个说法"，多数情况下两版质量相当；
- 真正会伤到用户的 I-8（数字幻觉）只涉及 5/387 条。

**但要强调**：I-3 之所以是 P0，不是因为它自己伤用户，而是因为它是 C-6 的上游——**它把不可复现性注入了分类器**。如果只修一处，修 I-3 的杠杆比修 I-8 大得多。

### 5.5 建议的处理顺序

1. **C-2**（清 L2 裸词 + 词边界）——最低成本、最高即时收益，能消掉 10.3% 的 L2 徽标错误
2. **C-6 + I-3**（切断循环依赖 / 让文案可复现）——恢复可调试性，是后面所有工作的前提
3. **C-1 + C-3**（低置信度不展示徽标 / 别把标签叫「因为」）——不改模型也能立刻降低误导
4. **R-1**（反馈最小事件量 + 置信下界）——如无并行重写覆盖则必须做
5. **I-1 + I-2**（禁词拆分 / 指纹纳入契约版本）——止血 token 与元数据脱钩
6. **R-2**（Explore 池补相关性或改呈现）

---

## 6. 建议建立的回归测试与监控指标

分成三层：**门禁式回归测试**（CI 里跑，红了不许合）、**产出体检**（每次 refresh/build 后自动算，超阈值告警）、**周期性人工校准**（无法自动化的部分）。

### 6.1 门禁式回归测试（CI，确定性，无外部依赖）

| ID | 测什么 | 判定 | 阈值依据 |
|---|---|---|---|
| **T1** 关键词词边界体检 | 对 `RULES ∪ SCENES_L2 ∪ _PATH_DESIGN_KEYS` 的每个 ASCII 关键词，在**固定的语料快照**上算「纯子串命中率」 | 任一关键词纯噪声率 **= 100%** → FAIL；**> 50%** 且命中 ≥ 10 篇 → FAIL；> 30% → WARN | 100% 意味着该词在语料上零判别力（现有 `bi`/`mom`/`zettel`/`marketplace` 会立刻红）。50% 是「一半以上证据是假的」这条直觉红线。10 篇下限避免长尾词刷屏 |
| **T2** 死规则体检 | 每个关键词在语料快照上的命中数 | 0 命中的关键词数 **> 语料词表的 10%** → WARN，并输出清单 | 当前 59/391 = 15.1%，已超。这个指标的价值是防止规则表虚胖，让 `biz-vertical` 只有 4 条这种事被看见 |
| **T3** 分类幂等性 | `apply_scene(x)` vs `apply_scene(normalize_item(apply_scene(x)))`，四个字段全比 | 任一字段不等 → **FAIL** | 这正是 C-5 的断言。`retag_scenes` 的 docstring 已经声称幂等，就该有测试守住它 |
| **T4** 分类确定性 | 同一输入连跑 2 次 + 打乱 `dict` 插入顺序后再跑 | 输出必须逐字段相同 | 当前通过（delta 0%），要防止将来引入 `set` 迭代顺序这类隐性不确定 |
| **T5** 黄金分类用例集 | ≥ 60 条人工标注的 (item, 期望 L1, 期望 L2)，覆盖每个行业 ≥ 5 条，且**必须包含全部已知历史坑**（`skill_path` 裸词、`JavaScript`/`script`、`build`/`ui`、`bitable`/`bi`、`promotion`/`motion`、`rapid`/`api`、`No database`/`database`、`Leonxlnx/taste-skill` 整仓污染） | L1 准确率 **< 85%** → FAIL；任一历史坑用例回归 → **FAIL** | 85% 对应「误判率 ≤ 15%」，是当前 20%（CI 上界 27.8%）之上一档可达的目标。历史坑零容忍——它们已经复发过一次（L1 修了 L2 没修） |
| **T6** i18n 硬约束校验器一致性 | 对每条 prompt 里声明的硬约束，构造一个刚好违规的假产出，断言 `_valid_fields` 拒绝它 | 任一约束在校验器里无对应检查 → **FAIL** | 直接封住 I-4 的根因：prompt 与校验器的约束集必须同构 |
| **T7** 缓存指纹敏感性 | 改 `BODY_LIMIT` / `SYSTEM_PROMPT` / `USER_TEMPLATE` / `DEFAULT_MODEL` / `temperature` 任一项，断言 `content_hash`（或新的契约指纹）改变 | 任一项改动后指纹不变 → **FAIL** | I-2。这个测试写起来只有几行，却能永久防住「换 prompt 不生效」 |
| **T8** 排序单调性 | 在 `rel_score ∈ [0, 1.5]` 上取 200 个点，断言 `personalize_score` 对 base 单调不减 | 出现下降 → **FAIL** | R-4。现在 `base=1.0→1.0`、`1.0001→0.5` 会立刻红 |
| **T9** 排序确定性与并列 | 同一输入两次 `rerank` 顺序相同；且打乱输入顺序后输出顺序不变 | 不一致 → **FAIL** | R-7。强制引入确定性 tie-break |
| **T10** 反馈灵敏度上界 | 用 1 条 / 3 条 / 5 条合成反馈，量 `rerank` 前后 top-10 重叠率 | 事件数 < 20 时 top-10 重叠率 **< 70%** → **FAIL** | R-1。当前 5 条事件下重叠率 0%，会立刻红。20 这个门槛的依据：低于此量的反馈无法把任何比例估计的 95% CI 收窄到 ±20pp 以内，不足以支撑重排 |
| **T11** 去重 | 服务 items 里 `id` 唯一、`(full_name, skill_path)` 唯一 | 有重复 → **FAIL** | R-6。当前 5 对重复会立刻红 |

### 6.2 产出体检（每次 refresh/build 后自动计算，写进 `feed.json`）

**分类器**

| 指标 | 定义 | 绿 / 黄 / 红 | 为什么这么定 |
|---|---|---|---|
| `scene_share_max` | 最大行业占比 | < 30% / 30–40% / **> 40%** | 历史事故是 71% 全落 `agent-tooling`；当前 `engineering` 34.0% 已在黄区。10 个桶均分是 10%，40% = 4 倍集中，超过就说明出现了吸收态 |
| `scene_other_rate` | 判为 `other` 的占比 | < 5% / 5–10% / > 10% | 当前 1.5%。**这个指标要双向看**：过低说明分类器不肯弃权（把不认识的硬塞进某个桶），过高说明覆盖不足。配合下一项一起读 |
| `low_conf_rate` | `scene_confidence ≤ 0.5` 的占比 | < 15% / 15–25% / **> 25%** | 当前 22.4%，实测该档准确率约 40%。这一档直接决定有多少张卡片带着近似随机的徽标 |
| `l2_empty_rate` | 无二级徽标的占比 | 5–20% 为健康 | 当前 6.7%。太低要警惕「又开始硬贴二级」——这正是已修过的历史问题，需要持续守 |
| `ascii_noise_share_in_why` | `scene_why` 里 ASCII 纯子串命中占全部展示关键词的比例 | < 3% / 3–8% / **> 8%** | 当前 9.3%，已在红区。这是 C-2 的在线代理指标，不需要标注就能算 |
| `unfounded_rate` | 消融掉 ASCII 纯子串命中后 argmax 翻转的条目占比 | < 3% / 3–6% / **> 6%** | 当前 7.2%（L1）/ 10.3%（L2）。它是「误判率」的**免标注下界估计**，可以每次构建都算 |
| `llm_dependent_label_rate` | 摘掉 i18n 字段后一级标签会变的条目占比 | **< 5%** 为目标 | 当前 23.5%。这个数字直接量化 C-6 的暴露面，修完之后应该趋近 0 |

**排序**

| 指标 | 定义 | 绿 / 黄 / 红 | 为什么这么定 |
|---|---|---|---|
| `rel_coverage` | 有 `rel_score` 的条目占比（含 corpus 池） | **100%** / 95–100% / < 95% | 当前 live 96.4%、corpus **0%**。任何进入排序的条目都必须有相关性信号，否则它的位置是假的 |
| `score_distinct_ratio` | 不同 `personal_score` 取值数 / 条目数 | > 0.8 / 0.5–0.8 / **< 0.5** | 当前 live 0.977（健康）、corpus **4/378 = 0.011**（严重）。这一项能一眼抓出 R-2 |
| `tie_group_rate` | 落在相同完整排序键上的条目占比 | < 5% / 5–15% / > 15% | 当前 live 3.6%、corpus 100% |
| `feedback_blast_radius` | 有 / 无 affinity 两次 `rerank` 的 top-10 重叠率 | > 80% / 60–80% / **< 60%** | 当前 **0%**。这是 R-1 唯一诚实的在线度量——它不看反馈有多少条，只看反馈实际改变了多少东西 |
| `feedback_events` | `feedback.jsonl` 有效事件数 | 记录并与上一项联读 | 5 条反馈造成 100% 头部变化 = 病态；5000 条造成 40% 变化 = 正常。**必须两个数一起看，单看任何一个都会误判** |
| `max_boost_over_sigma` | 单条可获最大反馈加成 / `personal_score` 的 σ | < 1.0 / 1.0–2.0 / **> 2.0** | 当前 0.70/0.189 = **3.7σ**。加成不该支配主信号，1σ 是「能改变名次但不能改变量级」的分界 |

**LLM 管线**

| 指标 | 定义 | 绿 / 黄 / 红 | 为什么这么定 |
|---|---|---|---|
| `constraint_violation_rate` | 至少违反一条硬约束的服务条目占比 | < 5% / 5–15% / **> 15%** | 当前 **24.0%**。修完 T6 之后这个数应该结构性归零（违规会被重试拦住） |
| `zh_en_pair_mismatch` | `highlights_zh` 与 `highlights_en` 条数不等的条目数 | **0** / — / ≥ 1 | 当前 2 条。双语一一对应是这一层的核心承诺，不该有容差 |
| `numeric_claim_unsupported_rate` | 中文文案里数字断言在原文找不到该数字的比例 | < 5% / 5–15% / **> 15%** | 当前 **23.8%**（5/21）。这是最便宜的幻觉代理指标，纯确定性回查，无需人工 |
| `cache_amplification` | `cards.jsonl` 行数 / 不同 key 数 | < 1.3 / 1.3–2.0 / **> 2.0** | 当前 **4.80x**。健康系统里每个键应该只在内容变化时增行，1.3 留出正常更新余量 |
| `same_hash_output_drift` | 同 `(key, hash)` 下存在 ≥2 份不同产出的键数 | **0** / 1–10 / > 10 | 当前 **169**。这是 I-3 的直接度量，也是 C-6 漂移风险的上游 |
| `permanent_failure_streak` | 同一 `(key, hash)` 连续失败的构建次数 | ≤ 1 / 2–3 / **≥ 3** | 连续 3 次失败 = 不是网络抖动，是逻辑上不可满足（`stitch-design-taste` 就属于这类）。这一项能自动把 I-1 那种「永久失败 + 永久烧钱」暴露出来，而现在它只体现为一个无人追查的 `failed=1` |
| `i18n_fallback_rate` | `i18n_ready=False` 的服务条目占比 | < 1% / 1–3% / > 3% | 当前 0.26%（1/388）。要和上一项联读：占比低但如果 streak 高，就是慢性出血 |
| `cache_writer_schema_count` | `cards.jsonl` 里不同键集合的行 schema 数 | **1** / 2 / ≥ 3 | 当前 **3**。缓存文件应只有一个写入方 |

### 6.3 周期性人工校准（不能自动化的部分）

| 项目 | 频率 | 方法 | 用途 |
|---|---|---|---|
| **分类标注集刷新** | 每季度，或规则表大改后 | 简单随机抽样 n ≥ 100（`N=400` 量级时，n=100 给 ±8pp 的 Wilson+FPC 精度，足够看出 5pp 以上的真实变化；要看 3pp 级变化需要 n ≈ 300，成本不划算） | 唯一能算真实误判率与校准表的来源。**固定随机种子并把种子写进报告**，让不同人复算得到同一样本 |
| **置信度校准表重估** | 同上 | 按 `scene_confidence` 原生取值分箱，算每箱准确率 + Wilson CI + ECE | ECE 目标 **< 0.05**（当前 0.117）。同时监控**方向一致性**：不应出现 0.5 档过度自信、0.65 档欠自信这种交叉 |
| **LLM 文案质量抽检** | 每月，或换模型 / 改 prompt 后**必查** | 抽 n = 30，人工评三项：忠实性（有无原文没有的功能）、中英语义一致性、是否像人话而非文档摘录 | 自动指标只能抓长度和数字。这次审计里定性忠实性表现良好（100 条里未见功能性幻觉），但换模型后必须重测——而由于 I-2，换模型**不会触发任何重译**，这个人工关卡是唯一防线 |
| **消融 vs 标注的比值追踪** | 每次标注时 | `真实误判率 / unfounded_rate` | 当前 20% / 7.2% ≈ 2.8。这个比值告诉你「免标注指标能覆盖多少真实错误」。比值稳定时可以放心用自动指标做日常监控；比值漂移说明出现了新的、消融抓不到的错误类型（比如中文通用词或分类学缺口），该重新标注了 |

### 6.4 关于阈值定法的说明

上面的绿黄红不是拍的，遵循三条：

1. **能锚定在已知事故上的，就锚定**。`scene_share_max > 40%` 锚定「71% 落 agent-tooling」；`ascii_noise_share_in_why > 8%` 锚定当前的 9.3%（即「现状即红线」，逼着先止血）。
2. **能锚定在统计功效上的，就锚定**。反馈最小事件量 20 来自「比例估计 CI 半宽 ≤ 20pp」；抽样量 n=100 来自「±8pp 精度」。
3. **剩下的用「结构性零容忍」**。`zh_en_pair_mismatch`、`same_hash_output_drift`、`cache_writer_schema_count`、`rel_coverage` 这几项的正确值是 0 或 1，不存在「可接受的少量违规」——它们不是质量指标，是契约指标。契约指标不设容差。

---

## 7. 复现方式

审计用的临时脚本与数据快照按约定已删除（原路径 `scripts/_tmp_qa_*`）。下表记录每个数字的计算方式，便于重建。全部分析都是**只读 + 纯内存**：`import scene / rank / i18n / feed_pack`，喂 `feed.json` 的条目，不写回任何东西。

| 分析 | 输入 | 方法要点 |
|---|---|---|
| 复现 delta（§0.3） | `feed.json.items` | 对每条跑 `scene.apply_scene(dict(it))`，与已存的 4 个字段逐一比对 |
| ASCII 地雷表（C-2） | `items + corpus` = 766 篇，`scene._hay()` | 对每个 ASCII 关键词比较「子串命中篇数」与「词边界命中篇数」（`(?<![a-z0-9])kw(?![a-z0-9])`）。**CJK 关键词不做此检验**——中文靠子串匹配是合理的，把 `技术写作者` 命中 `写作` 算污染会高估问题 |
| L1/L2 消融（C-2） | 同上 | 丢弃所有「只以子串形式命中」的 ASCII 命中，重算得分向量并重新取 argmax（复刻 `tag_scene` 的平局让位逻辑） |
| 误判率与校准表（C-1/C-3） | `feed.json.items` | 简单随机抽样 `seed=20260903, n=100`；人工对照 `one_liner_zh` + 英文 `description` 标注；Wilson 区间 + 有限总体校正 `sqrt((N-n)/(N-1))` |
| 两遍输入差异（C-5） | 构造条目 | `apply_scene` → `feed_pack.normalize_item` → `apply_scene`，比较四个字段 |
| 循环依赖（C-6） | `feed.json.items` | 从条目里摘掉 `one_liner_zh/en`、`who_for_zh`、`highlights_zh` 四个键，重跑 `apply_scene`，统计标签变化数 |
| 词表长度相关性（C-7） | `scene.RULES` + items | Pearson r（每行业关键词数占比，判到的条目占比），n=9 |
| 反馈反事实（R-1） | live 池 + `feedback.jsonl` | `rank.rerank(..., affinity=aff)` vs `affinity=None`，算 top-k 集合重叠与名次位移 |
| catalog 模拟（R-4） | items 文本 | 用 items 自身文本构造 3787 / 11091 规模的 `interest_toks`，重算 `rank.relevance_score`，看是否突破 1.0 |
| 约束遵守率（I-4） | `cards.jsonl` + items | 汉字数用 `[\u4e00-\u9fff]` 计数，英文词数按空白切分；逐条对照 prompt 里的 40/22/18/14/10/8 与「恰好 3 条」 |
| 缓存漂移（I-3） | `cards.jsonl` | 按 `(i18n.cache_key(row), row['hash'])` 分组，比较组内 `fields` 的 JSON 规范化串是否唯一 |
| 指纹覆盖（I-2） | — | 临时改 `i18n.BODY_LIMIT` 再算 `content_hash` 观察变化；`model` 未参与命中判定由 `i18n.py:291-299` 直接可读 |
| 数字幻觉（I-8） | items + `cards.jsonl` | 正则 `(\d+)\s*(?:种\|个\|张\|条\|层\|步\|套\|大\|多\|款\|类)` 抽取中文文案里的量化断言，回查该数字串是否出现在 `name + description + body_preview` |

**数据快照说明**：因为 `feed.json` / `cards.jsonl` 在审计期间被并行 agent 改写，本报告的数字对应 `generated_at = 2026-09-03T08:49:31Z` / `cards.jsonl = 2072 行` 那一版。重跑时如果数字有出入，先核对这两个基线值。

**本次审计未修改任何生产代码，未运行 `refresh` / `build` / `serve`，未产生 git 提交，未消耗任何 LLM 调用。`~/.skill-feed/` 下的运行时数据未被写入。**

---

**审计人**：Model QA Specialist（独立只读审计）
**审计日期**：2026-09-03
**建议下次复审**：C-2 / C-6 / I-3 修复后立即复审（这三项会改变几乎所有其他指标的基线）
