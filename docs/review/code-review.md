# skill-feed / skillfeeder 代码质量与架构评审

> **只读评审**。未修改任何生产代码。
>
> **代码快照时间点**：2026-09-03 16:46–17:00 (UTC+8)
> **基线 commit**：`10465b8` "Fix Feeds keywords: real lexicon only, no Chinese sliding fragments."（2026-08-11）
> **工作区状态**：16 个文件有未提交改动，与三个并行 agent 的在改文件重叠。本报告读到的
> `feed_dashboard.py` / `i18n.py` / `skillfeed.py` / `feed_pack.py` / `rank.py` / `server/`
> 均为该时刻的工作区版本（含未提交改动），不是 `10465b8` 的原始内容。
>
> **验证方式**：结论全部经过实际执行验证（临时探针脚本已删除），非静态推测。
> 单测跑过：`58 passed / 0 failed`（不是 42，用例已增长）。未运行 `refresh` / `build` / `serve`。
>
> **评审期间工作区发生了变化**（并行 agent 在提交新模块）。以下文件在我完成阅读**之后**
> 才出现，**未纳入本次评审**：`ranking.py`、`ranking_profile.py`、`impressions.py`、
> `star_history.py`、`server/ranking_service.py`、`server/ratelimit.py`、
> `docs/ranking-engine-design.md`、`docs/frontend-event-contract.md`。
> 从命名看，排序引擎正在往请求期服务化迁移 —— 方向与第 10 节"撑不住 #1/#2"一致，
> 那两条建议可能已在实施中，请对照新代码复核。
>
> **收尾时已复验所有 P0 仍然存在**（行号未变）：`feed_dashboard.py:28,741`（内联 payload）、
> `feed_dashboard.py:1657,1674,1688,2126`（URL 汇点）、`server/config.py`（默认密钥）、
> CSP 仍为 0 处、`gates.py` 的 `details` 追加仍在、`server/db.py` 仍无 WAL/busy_timeout、
> `server/app.py` 的 CORS allow-all 兜底仍在。
>
> **已按约定排除**（用户告知在修，未重复报告）：i18n 缓存键碰撞、分类关键词裸词误判、
> 中文路径 URL 未编码、卡片内容重复、排序规则缺失。

---

## 0. 一句话结论

**模板层存在一个可远程触发的、无需任何用户交互的存储型 XSS，攻击面是"任何人在 GitHub 上建一个仓库"。**
这是上线 skillfeeder.cn 前唯一的真正阻塞项，其余问题都可以带病上线后再修。

除此之外，架构上最大的债不是"哪个模块写得不好"，而是**个性化排序发生在构建期**——
这条决定了当前架构无法支撑"多用户 + 个性化"，需要的不是重构而是分层（详见第 10 节）。

---

## 1. 上线公网前必须修的 P0 清单

按修复顺序排列。前两条不修不能上线。

| # | 问题 | 位置 | 一句话后果 |
|---|---|---|---|
| **P0-1** | `feed.json` 原样内联进 `<script>`，第三方 SKILL.md 可断出脚本块 | `feed_dashboard.py:28,741` | 任意 GitHub 用户可在 skillfeeder.cn 上执行任意 JS |
| **P0-2** | `escapeHtml` 不校验 URL 协议，`javascript:` 直达 `href` | `feed_dashboard.py:1657,1674,1688,1747,2126` | 点击"打开 GitHub"即触发攻击者脚本 |
| **P0-3** | 服务端会话密钥硬编码兜底 `"dev-only-change-me"` | `server/config.py:22` | 漏配环境变量即可被任意伪造登录态，越权发布/操作 |
| **P0-4** | 生成的 HTML 无任何 CSP / 安全响应头 | `feed_dashboard.py:32-41` | P0-1/P0-2 无第二道防线，单点失守即全失守 |
| **P0-5** | `gates.details` 455 条内部门禁判定随页面公开 | `gates.py:78,142` + `feed_dashboard.py:741` | 泄漏内部打分口径、被拒仓库名单与阈值 |

**P0-3 补充**：`.env.example:2` 有 `SKILLFEED_SESSION_SECRET=change-me-...` 的提示，
但 `server/config.py:22` 用 `or "dev-only-change-me"` 兜底，`create_app()` 启动时
**不做任何校验**。方向：启动即校验，非本地环境用默认密钥直接拒绝启动，而不是打 WARN。

**P0-5 补充**：`gates.run_gates` 无条件把每个候选的判定写进 `summary["details"]`
（`gates.py:78` 初始化，`gates.py:142` 追加），实测 455 条 / 41.6 KB，随 `feed.json`
一起内联进 `index.html`。方向：`details` 只在本地诊断产物里保留，
`publish-site` 时从 payload 中剥离（这同时也是第 7 节体积问题的一部分）。

---

## 2. 模板层 XSS 风险专项

> 这是本次评审的最高优先级发现。**已实测复现**，不是理论风险。

### 2.1 数据来源是完全不可信的

`skill_detect.parse_skill_md`（`skill_detect.py:84-123`）把第三方仓库的 SKILL.md 切成
`name` / `description` / `keywords` / `body_preview` / `frontmatter`，其中
`body_preview = body[:800]`（`skill_detect.py:121`）是**原文逐字节保留**，无任何过滤。
这些字段经 `KEEP_KEYS` 白名单（`feed_pack.py:12-21`，含 `description` / `body_preview` /
`name` / `problem` / `highlights`）进入 `feed.json`。

小红书源同样引入不可信文本：`xiaohongshu.py:279` 的 `note_title` 最终成为条目
`description`，内容来自爬取的笔记标题。

**现网数据已证实这条链路是通的**：当前 `feed.json` 的 388 条 items 里，
**52 条的 `body_preview` 含 `<` 字符**，且已包含真实的标签字面量——

- `antfu/skills` 的 `description` / `problem` / `one_liner` / `body_preview` 四个字段
  都含 `<script setup lang="ts">`
- `aeonfun/aeon` 的 `body_preview` 含多处 `<!-- autoresearch: ... -->`
- `remotion-dev/skills` 含 `<Img>`、`<div>`
- `anthropics/skills` 含 `<!-- Slide number: N -->`

也就是说 `<script` 这个字面量**今天就已经出现在生产 `feed.json` 和 `feed.html` 里了**。
目前没爆，只是因为还没有人写出 `</script>` —— 这是运气，不是防御。

### 2.2 P0-1：`</script>` 断出（实测已复现）

```python
# feed_dashboard.py:28
payload = json.dumps(feed, ensure_ascii=False)
```

```python
# feed_dashboard.py:740-743
<script>
const FEED = {payload};
const SCENES = {scenes};
const SCENES_L2 = {scenes_l2};
```

`json.dumps` 只转义 `"` `\` 和控制字符，**不转义 `<` `>` `/`**。HTML 解析器在遇到
`</script` 时会无条件终止 script 元素，完全不管它在 JS 里是否处于字符串字面量内部。

**实测结果**（构造一条 `body_preview` 含 `</script><script>window.__XSS_PWNED=1</script>` 的条目）：

- 第一个 `<script>` 块**在第 203 个字符处被提前终止**
- 块内 `function cardHtml` 等全部 JS **消失**（`"function cardHtml" in block == False`）
- 注入的 `<script>window.__XSS_PWNED=1</script>` 成为**真实的、会执行的独立 script 标签**
- 载荷在 HTML 中原样出现（`PAYLOAD in html == True`）

**为什么严重**：无需登录、无需用户交互、无需诱导点击。攻击者只要建一个能过门禁的公开仓库
（`gates.py` 只看 star 数、来源、描述长度、关键词相关性 —— 见 2.5），SKILL.md 里塞一行
`</script>`，等一次 6 小时的 CI 刷新，恶意脚本就随 `index.html` 部署到 skillfeeder.cn。
拿到的是**站点同源的完整脚本执行权**：可读写 `localStorage`（`sf_liked` / `sf_saved` /
`sf_follow_builders`）、可读 `document.cookie` 中非 HttpOnly 部分、可向
`ui.api_base` 发起带凭证请求、可整页改写做钓鱼。

**方向**：不要试图"过滤 `</script>`"——那是黑名单思路，`<!--` 和 `<script` 同样能触发
script data double-escaped 状态。正确方向是**让数据离开 HTML 解析器的管辖范围**：
把 payload 放进 `<script type="application/json">` 之外的独立通道，或对内联 JSON 做
JS 字符串级转义（`<` `>` `&` `/` `U+2028` `U+2029` 全部转成 `\uXXXX`）后再嵌入。
前者更彻底。`publish-site` 已经在写独立的 `site/feed.json`（`skillfeed.py:705`），
让页面 fetch 它而不是内联，可以同时解掉这条和第 7 节的体积问题。

### 2.3 P0-2：`javascript:` 协议注入（实测已复现）

```javascript
// feed_dashboard.py:923-927
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  })[c]);
}
```

`escapeHtml` 对**文本节点和引号内属性值**是正确的，但 URL 协议不含任何被转义字符，
`javascript:alert(1)` 会原样通过。以下 10 处把 URL 放进 `href` / `src`：

| 位置 | 汇点 | 数据来源 | 风险 |
|---|---|---|---|
| `feed_dashboard.py:1688` | `<a class="open-gh" href>` | `it.url` | **高**：主 CTA，用户必点 |
| `feed_dashboard.py:1674` | `<a class="doc-link" href>` | `it.skill_url` | **高**：次 CTA |
| `feed_dashboard.py:2126` | `cta.href = url`（**零转义**） | `it.url` | **高**：Stories CTA |
| `feed_dashboard.py:1657` | `<img class="cover" src>` | `it.cover_url` | 中：`javascript:` 在 img 不执行，但可作外链探测/追踪 |
| `feed_dashboard.py:1747` | `<a class="pub-item" href>` | GitHub API `html_url` | 低：来源受控 |
| `feed_dashboard.py:1892,1893` | GitHub 搜索链接 | 内部构造 | 低 |
| `feed_dashboard.py:1944,1946,1947` | `ui.api_base` 派生 | 配置 | 低 |

**实测**：`feed_pack.normalize_item` **不会**清洗这三个字段——

```
url       = javascript:window.__XSS_HREF=1
cover_url = javascript:window.__XSS_COVER=1
skill_url = javascript:window.__XSS_SKILL=1
```

`normalize_item`（`feed_pack.py:58-103`）对它们只做 `or` 兜底：
`out["url"] = out.get("url") or (f"https://github.com/{fn}" ...)`（`feed_pack.py:64`）。
只要上游给了值就照抄。

**当前实际可达性**：主要采集源的 `url` 目前都是内部构造或经正则约束的
（`catalog_sources.py:200`、`github_search.py:105`、`xiaohongshu.py:404`、
`corpus.py:116`），所以**今天很可能还打不进来**。但这是巧合而非设计：
`normalize_item` 是全管线唯一的收口点，它**没有 URL 白名单**。
任何新源、任何 UGC 通路（`server/ugc.py` 已经在写 `url` / `skill_url` / `cover_url`）
或任何一次上游重构，都能在毫无提示的情况下打开这个口子。

**方向**：在 `normalize_item` 里做一次**协议白名单**收口（只允许 `https:`，
可选 `http:`），不合规就丢弃并回落到构造 URL；同时在客户端渲染前再挡一道，
`cta.href = url`（`feed_dashboard.py:2126`）这类直接赋值必须走同一个校验函数。
这是纵深防御的两层，任一层都不能省。

### 2.4 P0-4：无 CSP，失守即全失守

实测生成的 HTML 中 `Content-Security-Policy` / `X-Frame-Options` /
`X-Content-Type-Options` / `sandbox` / `integrity` 出现次数**全部为 0**。

页面同时从 `fonts.googleapis.com` / `fonts.gstatic.com` 加载外部 CSS
（`feed_dashboard.py:38-40`）、从 `opengraph.githubassets.com` 加载图片、
向 `api.github.com` 发 fetch（`feed_dashboard.py:1701`）。

**方向**：加 `<meta http-equiv="Content-Security-Policy">`。但注意——当前架构里
整个 JS 都是内联的，纯 CSP 需要 `'unsafe-inline'` 才能跑，那就基本没有防护价值。
所以 CSP 的前提是先把内联脚本外置成独立 `.js` 文件（GitHub Pages 支持），
这件事和 2.2 的"payload 外置"是同一个改造方向，应该一起做。

### 2.5 门禁挡不住攻击者

`gates.run_gates`（`gates.py:38-148`）的四道门是 `G_source` / `G_star` / `G_rel` / `G_parse`：

- `G_star`：`min_stars=20`（`config_defaults.json:2`）—— 20 个 star 不构成门槛
- **`star_exempt_sources` 包含 `github-search` / `catalog` / `xiaohongshu`**
  （`config_defaults.json:42-48`），这些源 `stars is None` 时**直接豁免星数门禁**
  （`gates.py:100-101`）
- `G_parse` 只要求 `len(name) >= 1 and len(desc) >= 10`（`gates.py:114-115`）
- `G_rel` 只要求关键词相关性 ≥ 0.15

**没有任何一道门检查内容安全性**。门禁是"选品"逻辑，不是"防御"逻辑——
把它当安全边界是错配。方向：安全过滤必须放在渲染层（2.2 / 2.3），不要指望门禁。

### 2.6 属性插值未统一转义（P2，当前不可利用）

实测有 29 处属性值插值绕过了 `escapeHtml`。逐个核对后，**当前都不可利用**：
`${idx}` 是循环下标，`${pal[0..2]}` 来自 `PALETTES` 常量，
`${softCls}` / `${focus}` / `${noCoverCls}` 是内部三元表达式，
`data-kind="${st.kind}"`（`feed_dashboard.py:1834`）和
`data-id="${it.id}"`（`feed_dashboard.py:1852`）分别来自内部 Stories 结构和 `SCENES` 常量。

但这是**"恰好安全"而不是"设计安全"**：`${it.id}`（`feed_dashboard.py:1852`）
用的是 scene chip 的 id，而条目也有 `it.id`（形如 `owner/repo::path`，含第三方仓库名）；
两者同名不同源，一次复制粘贴就可能串线。方向：属性插值一律走 `escapeHtml`，
不要靠"我知道这个变量是内部的"来豁免。

### 2.7 XSS 专项测试缺失

`tests/test_feed_dashboard.py` 309 行、13 个用例，**没有任何一个用例喂入恶意输入**。
没有 `</script>` 测试，没有 `javascript:` 测试，没有 `onerror=` 测试。

这是这类 bug 能存活到今天的直接原因。方向：加一组"注入语料"回归测试
（`</script>`、`<!--`、`"><img onerror>`、`javascript:`、`U+2028`），
断言生成的 HTML 里 script 块数量不变且载荷不以可执行形式出现。
这类测试很便宜，且能永久锁住回归。

---

## 3. 架构与耦合

### P1-1 `skillfeed.py` 是过载入口（979 行，11 个职责）

`skillfeed.py` 同时承担：CLI 参数解析（手写 `while i < len(argv)` 循环，**11 处重复**）、
配置加载、路径管理、六源编排、去重合并、i18n 调度、分类重跑、产物写入、
自我拷贝、**内嵌一个 HTTP 服务器**（`FeedHandler`，`skillfeed.py:801-858`）、
以及子进程调用。

具体证据：
- 手写 argv 解析在 `cmd_refresh` / `cmd_build` / `cmd_i18n` / `cmd_serve` / `cmd_api` /
  `cmd_corpus` / `cmd_publish_site` / `cmd_bitable` / `cmd_xhs_crawl` 各写一遍，
  模式完全相同且都有同一个 bug（见 P2-1）
- `cmd_refresh` 单函数 `skillfeed.py:312-605`，**294 行**，是整条管线的过程式脚本
- 源编排是**复制粘贴四遍**的 `try/except` + `print` 块
  （`skillfeed.py:383-398` search、`407-421` catalog、`430-440` xhs），
  每块结构一致但错误处理细节不一致（见 P1-6）

**后果**：`refresh` 无法被单元测试（只能整体跑，而整体跑要十几分钟且烧 LLM 调用）；
加第七个源需要在 `cmd_refresh` 里再抄一遍；改一处编排逻辑要同步改四处。

**方向**：把"源 → 候选行"抽成统一接口（每个源一个 `fetch(cfg) -> (rows, meta)`），
编排层变成对源列表的循环；把 `FeedHandler` 挪出主入口；argv 解析换成 `argparse`。
这些都不需要动数据结构，是纯机械拆分。

### P1-2 `KEEP_KEYS` 白名单：实测正在静默丢弃 22 个字段

```python
# feed_pack.py:97
slim = {k: out[k] for k in KEEP_KEYS if k in out and out[k] is not None}
```

`KEEP_KEYS` 有 32 个键（`feed_pack.py:12-21`）。实测喂一条"完整"上游条目进
`normalize_item`，**22 个字段被静默丢弃**：

```
catalog_hint, dir_name, frontmatter, gates, highlights_en, highlights_zh,
i18n_ready, keywords, note_url, one_liner_en, one_liner_zh, repo_description,
scene_confidence, scene_l2_confidence, scene_l2_label_en, scene_l2_why,
scene_label_en, scene_why, skill_paths, who_for_en, who_for_zh, xhs_note
```

其中 **`scene_label_en` / `scene_why` / `scene_confidence` / `scene_l2_label_en` /
`scene_l2_confidence` / `scene_l2_why` 全部不在白名单** —— 用户提到"曾被吞掉"的
`scene_why` / `scene_confidence` / `scene_label_en`，**在当前代码里仍然是被丢弃的**。
它们之所以在 `feed.json` 里还看得到，是因为 `retag_scenes`（`skillfeed.py:120-134`）
在 `normalize_item` 之后又跑了一遍分类把它们补回来了 —— 属于"被丢了又被补回"的巧合修复。

**这个巧合只覆盖 `items`，不覆盖 `corpus`。** 实测当前生产 `feed.json`：

| 字段 | items (n=388) | corpus (n=378) |
|---|---|---|
| `scene_label_en` | 388 / 100.0% | **0 / 0.0%** |
| `scene_l2_label_en` | 388 / 100.0% | **0 / 0.0%** |
| `scene_why` | 388 / 100.0% | **0 / 0.0%** |
| `scene_confidence` | 388 / 100.0% | **0 / 0.0%** |
| `one_liner_zh` | 387 / 99.7% | **0 / 0.0%** |
| `body_preview` | 378 / 97.4% | **0 / 0.0%** |

**这是一个正在生产环境发生的 bug**：`corpus` 池 378 条（占 feed 总量 49%）
**永久没有英文场景标签**。前端切到 EN 时，这批卡只能退回中文标签或裸 id。

**为什么这个设计有问题**：白名单的语义是"我列举出所有该保留的"，但上游有 6 个模块
在往条目上加字段（`skill_detect` / `gates` / `rank` / `scene` / `i18n` / `corpus`），
没有任何机制在新增字段时提醒你更新白名单。失败模式是**静默丢弃**，
而不是报错——这是最坏的失败模式，因为它只在下游某个渲染分支才表现出来。

**方向**：把白名单反转成**黑名单**（明确列出要丢的大字段：`body_preview` 原文、
`frontmatter`、`skill_paths`、`gates`、`details`），其余默认保留。这样新增字段的
默认行为是"通过"而不是"消失"。如果必须保留白名单，那就需要一个契约测试：
枚举各上游模块的产出字段，断言它们要么在白名单里、要么在显式的"已知丢弃"清单里，
新字段两边都不在就让测试失败。

### P1-3 顺序耦合：先分类 → 翻译 → 再分类

链路（`skillfeed.py:574-597`）：

```
pack_feed()          # scene.apply_scene 第 1 次，只看得到英文 SKILL.md
  └ normalize_item() # 抹掉 scene_why / scene_confidence / scene_label_en
run_i18n()           # 写入 one_liner_zh 等中文字段
retag_scenes()       # scene.apply_scene 第 2 次，这次能看到中文
```

`scene._hay`（`scene.py:271-292`）**确实会读 `one_liner_zh` / `who_for_zh` /
`highlights_zh`**（`scene.py:284-287`），注释也写明"i18n 产出的中文一句话是最强信号"。

**风险 1：分类结果依赖 i18n 是否成功，且不可观测。**
实测无 `DASHSCOPE_API_KEY` 且无缓存时，`enrich_items` 返回
`{'total': 1, 'skipped': 1, 'translated': 0}`，**不抛异常、退出码 0**，
只打一行 WARN（`skillfeed.py:117`）。此时 `retag_scenes` 的第二次分类看到的
和第一次完全一样，分类质量静默退化到"只看英文原文"的水平。
`feed.json` 里**没有任何字段**记录"这条的分类是在有译文还是无译文的情况下算出来的"，
事后无法审计。

**风险 2：`retag_scenes` 只处理 `items`。** 实测确认它只访问 `feed.get("items")`
（`skillfeed.py:127`），`corpus` 分支拿不到第二次分类 —— 这正是 P1-2 表格里
corpus 全 0 的直接原因。

**风险 3：`cmd_build` 会吃掉已有译文。** 实测：把一条带完整 i18n 字段的旧条目
喂进 `pack_feed`，输出的 7 个 i18n 字段**全部变成 `None`**：

```
输入: one_liner_zh = '把 Figma 设计系统一键搭起来。'
pack_feed 后: one_liner_zh = None
被丢弃: ['one_liner_zh','one_liner_en','highlights_zh','highlights_en',
         'who_for_zh','who_for_en','i18n_ready']
```

`cmd_build`（`skillfeed.py:632-636`）从旧 `feed.json` 取 items 当 `passed`，
经 `normalize_item` 洗掉译文，再靠 `run_i18n` 从 `cards.jsonl` 缓存贴回。
**译文的唯一真实存储是 `cards.jsonl` 缓存**，`feed.json` 里的只是副本。
一旦缓存文件损坏/被清、或内容 hash 变了而当时没有 API key，
**中文文案永久消失且无任何告警**（退出码仍是 0）。

**方向**：让分类只跑一次，跑在它需要的输入都就位之后（i18n 之后）；
或者显式把"分类输入完整度"作为条目字段落盘，让降级可观测。
更根本的是让 `pack_feed` 的瘦身步骤不要跨越 i18n 边界——
瘦身应该是**产物序列化前的最后一步**，而不是管线中段的一步。
`build` 复用旧 feed 时应视译文为权威数据而非可再生缓存。

### P1-4 `serve` 会触发完整 rebuild

`cmd_serve`（`skillfeed.py:867-869`）在启动前无条件调 `cmd_build([])`，
而 `cmd_build` 会调 `run_i18n`（`skillfeed.py:660`）—— 也就是
**`serve` 可能发起 LLM 调用并改写 `feed.json`**。一个"起个本地服务器看看"的命令
带有写产物 + 花钱的副作用，且没有 `--no-rebuild` 出口。方向：读写分离，
`serve` 只读现有产物。

### P2-1 11 处 argv 解析都有同一个 bug

```python
# skillfeed.py:615-621（cmd_build，其他 10 处同构）
while i < len(argv):
    if argv[i] == "--intent" and i + 1 < len(argv):
        ...
        continue
    print(f"unknown arg: {argv[i]}", file=sys.stderr)
    return 2
```

`cmd_build` 里 `print` 和 `return 2` **不在 `if` 块内**（`skillfeed.py:620-621`
缩进层级与 `while` 体同级），所以循环体第一次迭代若不匹配 `--intent` 就必然 `return 2`。
更关键的是：这个模式**没有 `else` 分支处理位置参数**，且各命令的实现细节不一致
（`cmd_bitable` 的 `skillfeed.py:980-981` 同样把 `print`/`return` 放在循环体末尾）。
方向：统一换 `argparse`，一次性消掉 11 份重复。

### 依赖方向（无循环依赖）

模块依赖是**单向的**，没有循环依赖，这一点是干净的：

```
skillfeed.py ──> 所有模块
feed_pack ──> highlights, rank, scene
gates ──> rank
corpus ──> hellogithub, scene
server/ugc ──> highlights, scene, skill_detect, feed_pack
feed_dashboard ──> scene
```

唯一的方向异味是 `server/ugc.py:10` 从根包 import `feed_pack.cover_url_for`——
服务端依赖了离线管线模块。量很小，但会拖着 `server` 无法独立部署。

---

## 4. 前端生成层（`feed_dashboard.py`）

### P1-5 f-string 拼 2437 行 HTML 的可维护性代价

实测数据：
- 模板体内**双写花括号 `{{` 出现 700 次、`}}` 出现 700 次**
- 真正的 Python 占位符只有 **4 个**：`{page_title}` / `{payload}` / `{scenes}` / `{scenes_l2}` / `{variant}`

也就是**为了 4 个插值点，付出了 1400 次手工双写**。

**这个约定有多容易出错**：
- 漏一个 `{` 的双写 → Python 抛 `KeyError` / `ValueError`，**构建期就炸**（这是好的失败模式）
- 但如果漏写的位置恰好构成一个合法的 Python 格式化表达式（比如 CSS 里的
  `{color}` 之类），就会**静默替换成错误内容**或抛 `NameError`
- 编辑器/linter 对 f-string 内部的 CSS/JS **完全无语法高亮、无补全、无格式化、无 lint**
- 2437 行里 JS 部分约 1500 行，全部处于"字符串内部"，任何 JS 工具链都碰不到

**当前有没有已经写错的地方**：实测扫描模板体内的单写花括号，只有 **2 处**，
都是 `<body class="variant-{variant}">`（`feed_dashboard.py:647`）—— 这是**正确的**
Python 占位符使用。**结论：目前没有双写错误。** 但这是靠人肉维持的，
且 700 对花括号意味着每次编辑 CSS/JS 都在赌。

**不重写整个架构的改善方向**（按性价比排序）：

1. **把 CSS 和 JS 抽成同目录下的 `.css` / `.js` 纯文本文件**，用 `Path.read_text()`
   读入后再拼。立刻消掉全部 1400 次双写，且 CSS/JS 恢复正常的编辑器支持和 lint。
   这一步不改变"单文件 HTML 产物"这个产品约束——读进来再内联即可，
   而且它同时是 2.4 节 CSP 改造的前置条件。**这是本节最值得做的一件事。**
2. **拆函数**：`build_feed_html` 现在是一个巨型 return。可以按区块拆成
   `_head()` / `_styles()` / `_body_shell()` / `_script()`，每个返回字符串片段。
   降低单次编辑的爆炸半径。
3. **加转义单测**：见 2.7。抽出 CSS/JS 后，`escapeHtml` 和 URL 校验就可以被
   node 直接单测，不必再走"生成 HTML → 正则抠 JS → 塞进 node"这条脆弱链路
   （`tests/test_feed_dashboard.py:15-38` 的 `_script_source` / `_top_level_functions`
   就是为了绕开这个问题手写的"伪 JS parser"，注释里也承认"不用真写个 JS parser"）。

**值得肯定的**：`JsHarness`（`tests/test_feed_dashboard.py:48-79`）在 node 里跑
模板生成的**真 JS** 来测去重规则，避免了在 Python 里抄第二份实现——
这是正确的测试设计，比断言模板源码字符串强得多。

---

## 5. 错误处理与健壮性

### P1-6 `refresh` 卡死 18 分钟的根因：探测无请求预算

用户提到的"refresh 挂住 18 分钟无输出"，根因是 `skill_detect.find_skill_paths`
（`skill_detect.py:194-236`）**单仓 HTTP 请求数无上界**，且**全流程无总超时**。

实测请求数上界推算（`_http_get` 默认 `timeout=20`，`skill_detect.py:127`）：

| 阶段 | 请求数 |
|---|---|
| `CANDIDATE_PATHS` 5 条 × 3 个 ref（HEAD/main/master，`skill_detect.py:166`） | 15 |
| `list_dir_api` 5 个 base 目录（`skill_detect.py:205`） | 5 |
| 一层目录 × 3 ref | entries × 3 |
| `DESCEND_CAP=12` 次下钻 × (1 + 子目录 × 3) | 最多 12 × 31 = 372 |
| `enrich_repo_multi` 重新抓取选中路径（`skill_detect.py:311`） | 20 × 3 = 60 |

| `skills/` 目录数 | 单仓请求数 | 20s 超时下最坏耗时 |
|---|---|---|
| 10 | ~420 | **140 分钟** |
| 20 | ~512 | **170 分钟** |
| 40 | ~572 | **190 分钟** |

一轮 `refresh` 探测约 **117 个仓**
（`search_probe_limit=25` + `catalog_probe_limit=35` + `xhs_probe_limit=20` + trending + hg）。
**没有全局请求预算、没有总 deadline、没有单仓请求上限。**
CI 的 `timeout-minutes: 45`（`.github/workflows/pages.yml:39`）是唯一的兜底，
而且 `refresh --force`（`.github/workflows/pages.yml:109`）**绕过所有缓存**，
把请求数拉到最大。

**方向**：三层预算。单仓请求数硬上限、单源耗时上限、整轮 deadline；
超预算就带 `partial=true` 标记提前收尾而不是无限等。
另外 `fetch_raw_skill` 对每个路径盲试 3 个 ref（`skill_detect.py:166`）
是 3 倍放大器——先解析一次仓库默认分支再定向请求，可直接砍掉 2/3。

### P1-7 `monorepo_expand_limit` 三处不一致，生效值是最大的那个

| 位置 | 值 |
|---|---|
| `skill_detect.DEFAULT_EXPAND_LIMIT`（`skill_detect.py:52`） | 6 |
| `skillfeed.py:463` 内联默认 | 6 |
| `config_defaults.json:23` | **20** |
| `skill_detect.FIND_PATHS_CAP`（`skill_detect.py:53`） | 24 |

`config_defaults.json` 总是被加载（`skillfeed.py:158`），所以**生效值是 20**，
代码里的 6 和文档注释"单仓最多展开 6 条"都是失效信息。
后果：单个 monorepo 最多霸占 20 张卡（当前 items 总数 388，即单仓可占 5%），
同时贡献 60 次额外 HTTP 请求。

### P1-8 `trending.py` 异常处理器内部会抛出未捕获异常

```python
# trending.py:249-259
except (urllib.error.URLError, ..., OSError) as e:
    _, json_path = cache_paths(data_dir, since)
    if json_path.exists():
        rows = json.loads(json_path.read_text(encoding="utf-8"))   # ← 第 253 行，无保护
```

`load_cached_repos`（`trending.py:202-205`）对同一个文件的读取**是有** `try/except
(json.JSONDecodeError, OSError)` 保护的，但降级路径的 `trending.py:253` **没有**。
而 `save_cache`（`trending.py:208-214`）是非原子写（见 P1-11），
缓存文件损坏是完全可能的。

叠加放大：`skillfeed.py:353` 调 `trending.fetch_trending` 时
**没有 try/except**，与其他四个源（`skillfeed.py:345` corpus、`383` search、
`407` catalog、`430` xhs 都有）不一致。
**结论：一个损坏的 `trending_daily.json` 会让整个 `refresh` 硬崩，且崩在异常处理器里。**

### P1-9 GitHub 403 被误报成"限流"

```python
# github_search.py:182-184
if code == 403:
    warns.append("rate limited on search/repositories")
    break
```

匿名访问 `api.github.com` 返回 403 表示**拒绝访问**，不是限流；限流是 403 + 
`x-ratelimit-remaining: 0` 或 429。当前把两者混为一谈，
`_http_json` 已经取回了 `x-ratelimit-remaining`（`github_search.py:53,132`）
却没用在判断上。运维看到"rate limited"会去等，而实际该做的是配 token。
`skillfeed.py:448` 的 WARN 文案是对的（"匿名会 403"），但源模块的诊断是错的。

### P1-10 静默失败面积（~60 处）

全仓 `except ...: pass|return|continue` 约 60 处。按危害分级：

**真正吞错误的（建议改）**：
- `skillfeed.py:164-165` — 用户 `config.json` 语法错误被完全吞掉，
  静默退回默认配置。用户改了配置没生效且不知道为什么。
- `i18n.py:131-132` — `cards.jsonl` 读取失败返回空 dict，
  被解读成"缓存全未命中"，触发全量重译（388 条 × token）。
- `corpus.py:47-48` / `corpus.py:104-105` / `corpus.py:132-133` /
  `corpus.py:198-199` — 索引读取和写入失败全部静默。
  `corpus.py:132` 单条 JSON 备份写失败时，`new_rows` 仍然会被追加进索引，
  造成索引与备份文件不一致。
- `skillfeed.py:908-909` — `webbrowser.open` 裸 `except`（`# noqa: BLE001`）。
- `server/auth.py:52-53` — `verify_session` 裸 `except Exception: return None`。
  签名验证失败和程序 bug 无法区分，排查登录问题时没有任何线索。
- `server/ugc.py:135-136` — `load_official_items` 吞掉全部异常返回 `[]`，
  官方源挂了表现为"feed 里只有 UGC"，无告警。

**`_call_model` 的失败塌缩（`i18n.py:226-237`）**：
2 个 `return None` 分支覆盖了网络错误 / HTTP 4xx / JSON 解析失败 / 字段校验不通过
四类完全不同的原因，**且不记录仓库名和原因**（实测确认无 `print`/`log`）。
统计只有一个 `failed` 计数（`i18n.py:324`）。
API key 配错时你会看到 `failed=388`，然后**无从下手**。

**方向**：区分"预期的降级"和"意外的错误"。前者继续静默但要计数并在摘要里体现，
后者至少打一行带上下文（哪个仓、哪个字段、什么异常）的日志。

### P1-11 长流程可观测性与中断续跑

`refresh` 十几分钟到 45 分钟，当前的可观测性是 `print` 到 stdout：
- **没有时间戳**，无法判断卡在哪一步多久
- **没有进度计数**（`_probe_candidates` 的 `skillfeed.py:230-233` 只在命中时打印，
  不命中的仓完全静默）—— 这就是"挂住 18 分钟无输出"的观感来源
- **完全不能续跑**：`cmd_refresh` 是一趟到底的过程式函数，
  中途失败/超时则本轮全部丢弃。CI 的 `cancel-in-progress: true`
  （`.github/workflows/pages.yml:34`）会主动 kill 正在跑的构建

**i18n 的续跑问题尤其贵**：`_append_cache` 在**整个线程池跑完之后才调用一次**
（`i18n.py:339-340`）。中途被 kill → 本轮已消耗的 token 全部白烧，缓存不落盘。
实测 388 条在最坏情况下需要 `388/4 × 60s ≈ 97 分钟`（`i18n.DEFAULT_WORKERS=4`,
`DEFAULT_TIMEOUT=60`），**超过 CI 45 分钟上限**，也就是说这个场景是可达的。
另外 `_call_model` 无重试、无退避、无全局 deadline。

**方向**：给每个阶段加带时间戳和进度的结构化日志；
i18n 改成流式落盘（每完成 N 条就 append）而不是最后一次性写；
把 refresh 拆成可独立重跑的阶段并落盘中间态，让"续跑"变成"重跑缺失的阶段"。

### 并发安全：i18n 实测是安全的

用户点名要看 `i18n.py` 的 `ThreadPoolExecutor` 共享状态。**实测结论：没有数据竞争。**

关键在 `i18n.py:321`——`for it, fields in pool.map(work, todo)` 的结果
在**主线程串行消费**：

- `work`（`i18n.py:314-317`）只读 `it` 并返回，不写任何共享容器
- `attach(it, fields)` / `stats[...] += 1` / `new_rows.append(...)`
  （`i18n.py:322-337`）全部在主线程的 for 循环体内
- `cache`（`i18n.py:269`）在进池之前就读完了，池内不访问

**这条是干净的，不需要改。** 唯一相关的隐患是 P1-11 说的落盘时机，
以及 `pool.map` 保序但会因单个慢请求阻塞后续结果消费（不影响正确性）。

另一处并发点值得一提：`FeedHandler` 跑在 `ThreadingHTTPServer`
（`skillfeed.py:895`）上，`do_POST` 并发调 `feedback.append_feedback`
（`feedback.py:40-41`）向同一文件 append。全仓**无任何锁**
（实测 `threading.Lock` / `fcntl` / `filelock` 出现次数为 0）。
因为只绑 `127.0.0.1` 且单行短写，实际风险低，但如果 feedback 迁到公网服务端就必须处理。

---

## 6. 数据一致性

### P0/P1-12 全仓没有一处原子写

实测：`os.replace` / `os.rename` / `NamedTemporaryFile` / `os.fsync` 在整个代码库
**出现次数为 0**。所有产物都是 `Path.write_text()` 直接就地覆盖：

| 文件 | 写入位置 | 大小 |
|---|---|---|
| `feed.json` | `skillfeed.py:596,662,951` | 2146 KB |
| `feed.html` / `feed.lite.html` | `feed_dashboard.write_feed_variants` | 1992 KB × 2 |
| `corpus/index.jsonl` | `corpus.py:52-59`（append） | 2908 KB |
| `i18n/cards.jsonl` | `i18n.py:136-144`（append） | 1760 KB |
| `trending_*.json` | `trending.py:208-214` | — |
| `cache/*.json` | `github_search.py:93-96`, `catalog_sources.py:156-159` | — |

**后果**：写 2 MB 文件的过程中崩溃/被 kill/磁盘满 → 留下**截断的半个文件**。
这不是理论风险，因为 CI 的 `cancel-in-progress: true`
（`.github/workflows/pages.yml:34`）会主动 kill 构建，
且 `actions/cache` 会把这个损坏文件**缓存下来带到下一轮**
（`.github/workflows/pages.yml:58-64`）。P1-8 说的"损坏的 trending 缓存让 refresh 硬崩"
就是这条的下游表现。

**方向**：写临时文件 + `os.replace` 原子替换（同分区上是原子的，Windows 上
`os.replace` 也能覆盖已存在文件）。这是一个局部的、低风险的改动，收益很高。

### P1-13 多产物之间无一致性保证

`feed.json` / `feed.html` / `feed.lite.html` 是**三次独立的写操作**
（`skillfeed.py:596-597`），中间任何一次失败都会留下版本错配的产物组合。
没有版本号、没有校验和、没有"这三个文件来自同一次构建"的标记
（`generated_at` 只在 `feed.json` 和内联 payload 里，`feed.html` 外部无从校验）。

`corpus/index.jsonl` 与 `corpus/github/repos/*/meta.json` 的双写
（`corpus.py:190-203`）也没有一致性保证：`meta.json` 写失败被静默吞掉
（`corpus.py:198-199`），但索引行照样追加。

**方向**：产物打包成一次原子发布（先全部写到临时目录，再整目录替换），
或至少给每个产物写入同一个 build id 供下游校验。

### P1-14 `cards.jsonl` 追加写膨胀：79.2% 是死数据

实测当前状态：

```
总行数        : 2072
唯一缓存键    : 432
冗余行        : 1640  (79.2% 是历史版本)
文件大小      : 1760.4 KB
当前 feed items: 388
重复最多的键  : earthtojake/text-to-cad(45 次), obra/superpowers(43),
                affaan-m/ECC(43), Leonxlnx/taste-skill(42), alinaqi/maggy(37)
```

用户提到的"205 条有效 / 877 行"已经涨到 **432 / 2072**。单键最多重复 **45 次**。

`_append_cache`（`i18n.py:136-144`）**只追加，永不压实**，而
`load_cache`（`i18n.py:114-133`）每次**读取并 `json.loads` 全部行**，
靠"后写覆盖先写"（`i18n.py:130`）取最新值。所以成本是双向的：
文件无限增长 + 每次 refresh/build/i18n 都要全量解析 2072 行（且会继续涨）。

同样的模式在 `corpus/index.jsonl`（2908 KB / 4210 行，`corpus.py:52-59` append）
和 `feedback.jsonl`（`feedback.py:40-41` append）上重复。
`corpus` 更糟：实测 `index.jsonl` 在**单轮 refresh 中被完整解析 4 次以上**——
`ingest_hellogithub` → `_load_index_keys`（`corpus.py:84`）、
`ingest_feed_skills` → `_load_index_keys`（`corpus.py:157`）、
`load_corpus_items`（`corpus.py:225`）、
`load_skill_candidates` → 又调一次 `load_corpus_items`（`corpus.py:264`）。

**方向**：加压实机制（保留每键最新一条 + 保留 `locked` 标记的行），
可以在每次 append 后按阈值触发，或作为独立子命令。
读取侧改成"读一次、进程内复用"，消掉单轮 4 次全量解析。
`feedback.jsonl` 需要按时间窗滚动（`rank.load_feedback_affinity` 已经只用最近 400 条，
`rank.py:181`，那么文件也没必要无限留）。

---

## 7. 产物体积（公网上线的第二个硬问题）

虽然用户没单独列，但这条严重程度接近 P0，且和 XSS 的修复方向重叠。

实测 `feed.html` 体积构成：

```
feed.html 总大小       : 1680.7 KB
其中 const FEED = ...  : 1582.5 KB  (94.2%)
```

`feed.json` 内部构成：

| key | 大小 | 占比 | 条数 |
|---|---|---|---|
| `items` | 1145.0 KB | 72.4% | 388 |
| `corpus` | 390.5 KB | 24.7% | 378 |
| `gates` | 41.8 KB | 2.6% | （含 455 条 details） |
| 其余 | 4.9 KB | 0.3% | — |

**问题**：
1. **1.68 MB 单文件、无分页、无懒加载**，首屏必须下载全部 766 条。
   面向中国大陆用户、GitHub Pages 无国内 CDN，这个体积是产品级问题。
2. `corpus` 池 378 条（390 KB）是"无限下滑补货"，**首屏根本用不到**却全量下发。
3. `gates.details` 455 条（41.6 KB）是**纯内部诊断数据**，既占体积又泄漏信息（P0-5）。
4. **`lite` 变体几乎没有瘦身**：实测 `feed.html` 1720997 字节 vs
   `feed.lite.html` 1720998 字节，差异只有 `<title>` 和 `variant-lite` class
   ——payload 完全相同，包括 `gates.details`。
   `feed_dashboard.py` 的 lite 只是 CSS/JS 门控隐藏 UI，**没有裁剪数据**。

**方向**：`publish-site` 时按用途裁剪 payload（首屏 N 条内联，其余走
独立 `feed.json` / 分片按需 fetch，`site/feed.json` 已经在写了）；
`gates.details` 和 `corpus` 从内联 payload 中剥离；lite 变体真正裁数据。
这与 2.2 的 XSS 修复是**同一个改造**——payload 外置后两个问题一起解决。

---

## 8. 配置管理

### P1-15 `gate_profile` 是死配置（实测）

```
gate_profile=loose     -> resolve_thresholds = (20, 0.15, 'loose')
gate_profile=standard  -> resolve_thresholds = (20, 0.15, 'standard')
gate_profile=strict    -> resolve_thresholds = (20, 0.15, 'strict')
```

**三个 profile 得到完全相同的阈值。** 原因：`gates.resolve_thresholds`
（`gates.py:33-34`）优先取 `cfg.get("min_stars", base["min_stars"])`，
而 `config_defaults.json:2-3` **同时硬编码了** `min_stars: 20` / `min_rel: 0.15`，
所以显式值永远覆盖 profile。

移除这两个键后 profile 才生效：

```
loose     -> (5, 0.05, 'loose')
standard  -> (20, 0.15, 'standard')
strict    -> (50, 0.25, 'strict')
```

`gate_profile` 还被写进用户配置初始化（`skillfeed.py:178`）、
写进 `feed.json` 的 `config`（`skillfeed.py:586`）、在 `check` 里打印
（`skillfeed.py:790`）—— 一个完全无效的旋钮被当成有效的对外暴露了三次。
运维改 `gate_profile` 会发现"改了没反应"。

**方向**：二选一。要么 `config_defaults.json` 去掉 `min_stars`/`min_rel`，
让 profile 成为唯一入口 + 显式覆盖为可选；要么删掉 `gate_profile` 这个概念。
现状是最坏的——两套机制并存且一套静默失效。

### P1-16 影子默认值（实测 3 处不一致）

`skillfeed.py` 里的 `cfg.get(key, 内联默认值)` 与 `config_defaults.json` 冲突：

| 键 | 代码内联 | `config_defaults.json` | 位置 |
|---|---|---|---|
| `catalog_max_repos` | 50 | **60** | `skillfeed.py:414` |
| `monorepo_expand_limit` | 6 | **20** | `skillfeed.py:463` |
| `user_agent` | `"skill-feed/0.1"` | `"skill-feed/0.3 (+local; recommend-only)"` | `skillfeed.py:337` |

因为 `config_defaults.json` 总会被加载（`skillfeed.py:158`），
内联默认值**全部是死代码**。危害是认知性的：读代码的人（和 AI agent）会以为
`monorepo_expand_limit` 是 6，实际是 20（见 P1-7）。且一旦有人从
`config_defaults.json` 删掉某个键，行为会静默切换到另一个值。

### P1-17 四层配置的优先级与影子配置

实际优先级链（从低到高）：

```
1. 函数签名默认值        (如 catalog_sources.fetch_catalog_candidates 的 max_repos=60)
2. skillfeed.py 内联默认  (cfg.get(k, X)) —— 实际不可达，见 P1-16
3. config_defaults.json  (35 键，总是加载, skillfeed.py:158)
4. ~/.skill-feed/config.json (10 键，dict.update 覆盖, skillfeed.py:163)
5. 环境变量              (仅 SKILLFEED_HOME / GITHUB_TOKEN / GH_TOKEN /
                          DASHSCOPE_API_KEY / DASHSCOPE_BASE_URL)
```

**问题 1：环境变量的优先级不一致。**
- `GITHUB_TOKEN`：config 优先（`skillfeed.py:267-271`，`cfg.get("github_token")` 在前）
- `DASHSCOPE_API_KEY`：config 优先（`skillfeed.py:96-98`）
- `DASHSCOPE_BASE_URL`：**环境变量优先**（`i18n.py:268`，`os.environ.get(...) or base_url`）

同一类配置三种规则，其中 `DASHSCOPE_BASE_URL` 反向。CI 里靠这个反向行为工作
（`.github/workflows/pages.yml:107`），本地则相反 —— 这是个陷阱。

**问题 2：用户配置无 schema 校验，拼错静默失效。**
实测当前 `~/.skill-feed/config.json` 有 10 个键，其中
**`default_host` 在 `config_defaults.json` 里不存在**。
`load_config` 用 `defaults.update(user)`（`skillfeed.py:163`）无条件合并，
未知键既不报错也不警告 —— 无从判断这是"新功能的键"还是"打错的键"。

**问题 3：`ensure_data_dir` 只把 9 个键写进用户配置**（`skillfeed.py:172-184`），
另外 26 个键用户完全不知道存在，只能读源码。

**方向**：单一配置加载器 + 显式 schema（键名 + 类型 + 来源优先级），
未知键给 WARN，环境变量优先级统一成一套规则。

### 密钥处理：产物文件已验证干净

用户特别问 `feed.html` 是否含密钥。**实测结论：干净，可以分发。**

初始扫描在 `feed.json` / `feed.html` / `feed.lite.html` 中命中 7 次 `sk-[A-Za-z0-9\-]{10,}`，
逐个核对后确认是**误报**——唯一匹配是字符串 `'sk-proof-loop'`，
来自仓库名 `DenisSergeevitch/repo-task-proof-loop` 中的 "ta**sk-proof-loop**"。

其他核对：
- `feed["config"]`（`skillfeed.py:582-588`）只含 `min_stars` / `min_rel` / `since` /
  `gate_profile` / `intent`，**不含密钥字段**
- `feed["meta"]["sources"]`（`skillfeed.py:556-561`）内联了各源的 `meta`。
  这些 meta 含 status / remaining / warn 等，**不含 Authorization 头或 token**
- `i18n` 段（`i18n.py:367-373`）只写 model / updated_at / stats / languages
- `self_copy()`（`skillfeed.py:187-192`）只拷 `TOOL_FILES` 里的源码，**不拷 `config.json`**

**仍需注意的两点**：
1. `~/.skill-feed/config.json` 里**明文存着** `dashscope_api_key` 和
   `bitable_base_token`（实测这两个键都在用户配置里）。文件本身不进产物，
   但 `self_copy` 把工具拷进同一目录，任何"打包 `~/.skill-feed/` 分享"的操作都会泄漏。
   建议密钥只走环境变量/keyring，不落 config 文件。
2. `_http_json` / `_http_text` 在出错时把响应体放进 `meta["warn"]`
   （`github_search.py:187`、`catalog_sources.py:122`），而 `meta` 会进 `feed.json`。
   GitHub 的 4xx 响应体不含 token，但这是一条"上游响应原文 → 公开产物"的通路，
   值得收紧成只保留 status + 固定文案。

---

## 9. 测试质量

**现状**：11 个测试文件、**58 个用例**（不是 42，已增长）、全部通过、总耗时 1.5 秒。
**无真实网络依赖**（1.5 秒的总耗时和全仓无 `urlopen` mock / 全部用 fixture + tempdir 可以互相印证）。

### 覆盖分布

| 模块 | 测试文件 | 评价 |
|---|---|---|
| `gates` | `test_gates.py` (160 行) | 覆盖较好 |
| `rank` / `scene` / search | `test_search_rank_scene.py` (219 行) | 覆盖较好 |
| `feed_dashboard` | `test_feed_dashboard.py` (309 行) | **两极分化，见下** |
| `bitable_store` | `test_bitable_store.py` (113 行) | 有覆盖 |
| `feed_pack` | `test_feed_pack.py` (61 行) | **薄** |
| `highlights` | `test_highlights.py` (24 行) | **很薄** |
| `trending` | `test_trending.py` (25 行) | **很薄**（HTML parser 200 行，测试 25 行） |
| `skill_detect` | `test_skill_detect_priority.py` (34 行) | **只测 `path_priority` 排序** |
| `catalog` / `xhs` | `test_catalog_xhs.py` (40 行) | **很薄** |
| `server` | `test_server_api.py` (66 行) | **薄** |
| `publish-site` | `test_publish_site.py` (59 行) | 有覆盖 |

### P1-18 覆盖率盲区（按风险排序）

1. **模板转义 / XSS —— 零覆盖**。这是本报告第 2 节所有 P0 能存活的直接原因。
2. **`i18n.py` —— 零测试文件**。321 行，含缓存键逻辑、字段校验
   （`_valid_fields`）、并发调度、hash 比对。用户提到的"i18n 缓存键碰撞"
   正是没有测试的区域。
3. **`skill_detect.find_skill_paths` / `enrich_repo_multi` —— 零覆盖**。
   `test_skill_detect_priority.py` 只测了 `path_priority` 这个纯函数排序，
   而 monorepo 展开、DESCEND 下钻、请求预算（P1-6 的核心）完全未测。
4. **`corpus.py` 269 行 —— 无独立测试**，只在 `test_feed_pack.py` 里被间接调用。
   压实、索引一致性、`attach_body_previews` 都未测。
5. **`feedback.py` / `rank.load_feedback_affinity` —— 无覆盖**。
6. **错误路径几乎全未测**：缓存损坏、无 token、API 失败、磁盘写失败
   （P1-8 那个"异常处理器内部抛异常"就是这类）。
7. **`KEEP_KEYS` 契约无测试**。`test_feed_pack.py:55-58` 断言了
   `one_liner` / `cover_url` / `problem` / `highlights` 存活，
   但**没有任何用例断言 i18n 字段或 `scene_*_en` 字段存活**——
   这正是 P1-2 那些字段被反复吞掉却没被测试拦住的原因。

### P1-19 脆弱测试：断言模板源码而非行为

`test_feed_dashboard.py:182-209` 的 `test_build_contains_items_and_open_github`
单个用例里有 **~28 个 `assertIn`/`assertNotIn`**，其中大部分断言的是
**模板源码字符串**而非渲染行为：

```python
self.assertIn("extractHighlightsClient", html)      # 函数名
self.assertIn("countMode", html)                     # 函数名
self.assertIn("object-fit: contain", html)           # CSS 属性值
self.assertNotIn("background-size: cover; background-position: center;", html)
self.assertIn("const IS_LITE = VARIANT === 'lite'", html)   # 一行 JS 源码
self.assertIn("${hl ? `<ul class=\"highlights\">", html)     # 模板字面量片段
self.assertIn("path:**/SKILL.md", html)
self.assertNotIn("filename:SKILL.md ${", html)
```

**为什么是问题**：这些断言把"实现长什么样"钉死了。重命名一个 JS 函数、
调整一行 CSS 格式、给三元表达式换个写法 —— 行为完全不变，测试却红。
反过来，它们**不能保证任何行为正确**：`assertIn("countMode", html)`
只说明模板里有这 8 个字符，不说明模式计数是对的。

这类测试的净效果是**提高重构成本、降低重构意愿**——恰好和第 4 节
"抽出 CSS/JS 以改善可维护性"的方向直接冲突：一旦把 CSS 抽成文件，
`assertIn("object-fit: contain", html)` 之类还能过（内联后仍在 html 里），
但 `assertNotIn("filename:SKILL.md ${", html)` 这种对 f-string 语法的断言就会脆。

**对比**：同一文件里的 `TestCardDedupeJs`（`test_feed_dashboard.py:246-340`）
用 `JsHarness` 在 node 里跑真 JS、断言 `cardHtml` 的**输出**——
这是正确的行为测试。方向：把源码字符串断言收敛成少量"关键契约"断言
（比如"lite 不含关注按钮"应该断言渲染结果而不是断言 CSS 选择器存在），
其余交给 `JsHarness` 式的行为测试。

### P1-20 node 缺失时静默跳过全部行为测试

```python
# tests/test_feed_dashboard.py:246
@unittest.skipIf(NODE is None, "需要 node 才能跑模板里的卡片 JS")
```

本机有 node，58 个用例全跑（输出无 `s`）。但 **CI 没有 `setup-node`**
（`.github/workflows/pages.yml` 全文无 node 步骤），
所以在 CI 环境里这批**唯一的行为测试会全部静默跳过**，只剩脆弱的源码字符串断言。

### P1-21 CI 根本不跑测试

`.github/workflows/pages.yml` 的 `build` job 步骤是：
checkout → checkout HelloGitHub → setup-python → cache → 写 config →
`refresh --force` → `publish-site` → upload artifact。

**没有任何一步执行 `python -m unittest`。** 也就是说 58 个用例只在本地手动跑，
每 6 小时自动部署到公网的构建**完全没有测试门禁**。

**方向**：CI 加一个独立的 test job（含 `setup-node`），
且让 `deploy` 依赖它通过。这是成本最低、收益最高的一条改进。

---

## 10. Python 工程规范

### P1-22 完全没有 linter / formatter / type checker 配置

实测缺失：`pyproject.toml`、`setup.cfg`、`.ruff.toml`、`ruff.toml`、`.flake8`、
`mypy.ini`、`.pre-commit-config.yaml`、`tox.ini`、`Makefile`、`.editorconfig`
—— **全部不存在**。

有意思的是代码里散布着 `# noqa: BLE001`（`skillfeed.py:225,348,394,417,434,908`、
`server/auth.py:52` 等）——**这些 noqa 是写给一个并不存在的 linter 的**。
说明作者知道该有 lint，但从未接进来。

**方向**：接 `ruff`（一个工具同时覆盖 flake8/isort/pyupgrade 等，零配置起步）。
优先开 `BLE`（裸 except，直接命中第 5 节）、`S`（bandit 安全规则，
会命中第 2 节的部分问题）、`F`（未使用变量/导入）。
`mypy` 可以后置，因为类型标注还不完整（见下）。

### P2-2 类型标注：覆盖尚可，但精度低

**好的部分**：所有模块都有 `from __future__ import annotations`；
函数签名普遍标注了参数和返回值；用了 `Optional` / `tuple[...]` / `list[dict]`
等现代写法。

**精度问题**：
- `dict` 满天飞。核心数据结构"条目"（item）在整条管线里就是裸 `dict`，
  流经 `skill_detect` → `gates` → `rank` → `scene` → `feed_pack` → `i18n` →
  `feed_dashboard`，**没有任何类型描述它有哪些字段**。
  这是 P1-2（`KEEP_KEYS` 静默丢字段）能反复发生的根本原因之一——
  如果 item 是个 `TypedDict` 或 dataclass，加字段忘了同步白名单
  是可以被静态检查出来的。
- 返回 `dict[str, Any]`（`feed_pack.py:160`、`server/app.py:58` 等）等于没标注。
- `trending.py` 里 `TrendingRepo` 用了 `@dataclass`（`trending.py:19-27`）——
  **这是全仓唯一一个结构化数据类型，也证明这个模式在本项目里是可行的**。
  管线的 item 完全可以照做。
- `FeedHandler.log_message(self, fmt: str, *args)`（`skillfeed.py:804`）
  `*args` 无标注。

**方向**：给"条目"定义一个 `TypedDict`（哪些字段必需、哪些可选），
这一步的收益远超其他类型改进——它把 P1-2 从"运行时静默丢数据"
变成"静态可检查"。不需要一次改完，可以只在 `feed_pack` 的边界上用。

### P1-23 依赖管理：无 `requirements.txt`，版本未锁定

- **根本没有 `requirements.txt`**。离线管线号称"纯标准库"
  （`catalog_sources.py:4` 注释"纯标准库，无第三方依赖"），
  实测确实只用 `urllib` / `json` / `re` / `pathlib` / `concurrent.futures`
  —— 这是个不错的设计决策，值得保留。但**这一点没有任何地方声明或验证**，
  哪天有人 `import requests` 也不会被拦住。
- `requirements-server.txt` 只有 4 行，且**未锁定版本**。
  服务端依赖 `fastapi` / `uvicorn` / `httpx` / `pydantic`——
  pydantic v1→v2 是破坏性变更，`server/app.py:30` 用了
  `Field(pattern=...)`（v2 语法，v1 是 `regex=`），不锁版本迟早炸。
- 无 lockfile，无 `python_requires`。CI 用 Python 3.12
  （`.github/workflows/pages.yml:56`），本机是 3.14
  （`__pycache__` 里是 `cpython-314`）—— **两个版本差两个大版本且无声明**。

**方向**：加 `requirements.txt` 显式声明离线管线"无第三方依赖"（空文件 + 注释也行，
或用一个 CI 检查断言 `pip list` 干净）；`requirements-server.txt` 锁到
`==` 或至少 `~=`；声明 `python_requires` 并让 CI 矩阵覆盖本机版本。

### P1-24 性能陷阱

1. **`corpus/index.jsonl` 单轮 refresh 全量解析 4+ 次**（详见 P1-14），
   当前 2908 KB / 4210 行。
2. **`cards.jsonl` 每次全量解析 2072 行取 432 个有效键**（P1-14），79.2% 是死数据。
3. **`fetch_raw_skill` 的 3 倍请求放大**（`skill_detect.py:166`）：
   每个候选路径盲试 HEAD/main/master。这是 P1-6 请求量爆炸的主要乘数。
4. **`server/ugc.py:126-139`：`/api/feed` 每请求远程拉取完整 `feed.json`**，
   **无任何缓存**。当前 `feed.json` 1.5 MB —— 每个 API 请求都是
   一次 1.5 MB 下载 + 完整 JSON 解析。QPS 一上来立刻雪崩。
5. **`server/db.py:78`：`db_session` 每请求新建 SQLite 连接**，
   无连接池、无 WAL、无 `busy_timeout`。
6. **`feedback.summarize`（`feedback.py:45-75`）把整个文件读两遍**
   （一遍正向统计、一遍反向取 recent），且它是一个 HTTP 端点
   （`skillfeed.py:840-841`）。
7. **`rank.relevance_score` 的 `df` 表每轮重算**（`gates.py:68`
   `rank.build_df(docs)`），对所有候选的全文分词。候选量增长时是 O(n·m)。
8. **`server/app.py:68,73`：模板文件每请求从磁盘读取**，无缓存。

### P2-3 其他

- `skillfeed.py:284` 在函数体内 `import subprocess`（`cmd_xhs_crawl`），
  与文件顶部的导入风格不一致。
- `_probe_candidates`（`skillfeed.py:201-234`）的 `probed` 计数在
  `try` 之前自增（`skillfeed.py:220`），所以它统计的是"尝试数"而非"成功探测数"，
  但 funnel 里叫 `probed`（`skillfeed.py:570`）——指标名与语义不符。
- `skillfeed.py:1071-1072` 保留了 `install` 命令的墓碑分支，
  只为打印一句"已移除"。
- 仓库根目录有未清理的临时文件：`_tmp_probe.py`（62 行）。

---

## 11. 架构层面的建议

问题：要支撑「**多用户线上站点 + 每日自动刷新 + 个性化排序**」，当前架构哪里先撑不住？

按"撑不住的先后顺序"排列。前三条是**架构性**的（不改架构就做不到），
后面是**工程性**的（可以增量修）。

### 撑不住 #1：个性化排序发生在构建期 —— 这是最根本的错配

当前排序全部在离线管线完成：`rank.rerank(live, affinity=aff, intent=intent)`
（`feed_pack.py:170,175,189`），结果作为 `personal_score` / `personal_why` / `rank_why`
**烧进静态 `feed.json`**（`KEEP_KEYS` 里这三个字段都在，`feed_pack.py:18`）。

而 `affinity` 来自 `rank.load_feedback_affinity(DATA_DIR)`（`skillfeed.py:539`），
读的是**构建机上的** `~/.skill-feed/feedback.jsonl`——实测该文件当前只有 5 行。

**这意味着：所有访客拿到的是同一份排序，而这份排序反映的是"构建机器的口味"。**
"个性化"在当前架构下名不副实。前端只能靠 `localStorage`
（`feed_dashboard.py:891-894` 的 `sf_liked` / `sf_saved` / `sf_follow_*`）
做客户端重排，做不到真正的 per-user 排序，且换设备即丢。

**为什么这是第一位**：这不是性能问题也不是 bug，是**分层错误**。
排序是请求期（per-user）的关注点，被放进了构建期（global）。
其他所有问题都能靠打补丁缓解，这条不行。

**方向**：把"内容生产"和"排序服务"切开。离线管线只负责产出**无序的、带特征的**
候选集（`rel_score` 和内容特征保留，`personal_score` 移除）；
排序移到请求期，输入是"候选集 + 该用户的画像"。
`rank.personalize_score`（`rank.py:247-307`）本身是纯函数、逻辑可复用，
搬到服务端不需要重写——难的是下面第 2 条。

### 撑不住 #2：反馈/画像的数据模型是单机文件，多用户下直接失效

`feedback.jsonl` 是**构建机上的本地文件**（`feedback.py:19-20`），
写入路径是 `skillfeed.py serve` 内嵌的 HTTP 服务器
（`skillfeed.py:845-858`，只绑 `127.0.0.1`）。

但公网站点是 **GitHub Pages 静态托管**（`skillfeed.py:695` 设
`ui["hosting"] = "pages"`、`ui["feedback"] = "local-only"`）——
**Pages 没有后端，前端的反馈 POST 无处可去**。代码自己也承认这点
（`feedback = "local-only"`）。

所以现状是：线上用户的行为**完全没有被采集**，个性化没有输入。
而 FastAPI 服务端（`server/`）有 `reactions` 表（`server/db.py:43-51`）
和 `/api/posts/{id}/react`（`server/app.py:235`），但**只针对 UGC 帖**，
和离线 feed 的 388 条内容是**两套互不相通的数据模型**
（`feedback.jsonl` 按 `full_name`+`scene` 记，`reactions` 按 `post_id` 记）。

**方向**：统一成一套服务端事件流（用户 × 内容 × 动作），
覆盖离线 feed 内容和 UGC 两类对象；画像从事件流实时/近实时聚合。
这条是第 1 条的前置——没有 per-user 数据，请求期排序也无从个性化。

### 撑不住 #3：1.68 MB 单文件产物 + 全量内联

详见第 7 节。当前 766 条内容 → 1.68 MB / 页，其中 94.2% 是内联 JSON。

**增长曲线是线性的且没有任何缓冲**：条目数翻倍 = 页面体积翻倍。
2000 条就是 4 MB+。面向中国大陆用户、GitHub Pages 无国内 CDN，
这个体积在移动网络下是产品级障碍。

同时它也是 **P0-1 XSS 的载体**、**P0-5 门禁泄漏的载体**。
三个问题、一个修复方向。

**方向**：payload 外置 + 首屏分片 + 按需 fetch。
`publish-site` 已经在写独立的 `site/feed.json`（`skillfeed.py:705`），
基础设施是有的，只是页面没用它。

### 撑不住 #4：`refresh` 是不可中断、不可续跑、无预算的单趟流程

详见 P1-6 / P1-11。单仓最坏 400-570 次 HTTP、117 个仓、无总 deadline，
CI 45 分钟超时是唯一兜底，而 `--force` 把请求量拉满。
中途失败/被 kill → 本轮全丢（i18n 的 token 也白烧）。

"每日自动刷新"要求的是**幂等 + 可续跑 + 有预算**，当前三个都不满足。
`cancel-in-progress: true`（`.github/workflows/pages.yml:34`）
叠加非原子写（P1-12），还会把损坏产物缓存到下一轮。

**方向**：阶段化 + 中间态落盘 + 三层请求预算（单仓/单源/整轮）；
产物原子发布。

### 撑不住 #5：SQLite 每请求新连接，无 WAL / 无池 / 无 busy_timeout

`server/db.py:60-64` 每次 `db_session` 都 `sqlite3.connect(...)`
（`server/db.py:78`），且 `init_db` 在 `create_app` 时执行一次
（`server/app.py:36`）。没有 `PRAGMA journal_mode=WAL`、
没有 `busy_timeout`、没有连接池。

单用户没问题；一旦有并发写（发帖 + 点赞），SQLite 默认的
rollback journal 模式会立刻出现 `database is locked`。

**方向**：短期开 WAL + `busy_timeout` + 复用连接；
中期若写并发确实上来，换 Postgres。

### 撑不住 #6：`/api/feed` 每请求拉 1.5 MB 官方源

`server/ugc.py:126-139` 无缓存，且 `except Exception: return []` 静默降级。
`server/app.py:164-165` 在 `source in ("all","official")` 时**每个请求都调它**。

叠加 `merged[offset:offset+limit]`（`server/app.py:182`）——
为了返回 40 条，先下载并解析全部 766 条。

**方向**：官方源加进程内 TTL 缓存（甚至直接和内容库合并存储）；
分页下推到存储层而不是在内存里切片。

### 撑不住 #7：管线契约靠白名单人肉维护

`KEEP_KEYS`（P1-2）+ 多次分类（P1-3）+ 影子配置（P1-15/16）
共同构成一个"隐式契约"体系：6 个上游模块往裸 `dict` 上加字段，
一个 32 项白名单决定谁能活，两次分类靠调用顺序补救丢失的字段。

实测代价：22 个字段被丢、378 条 corpus 永久缺英文标签、
`gate_profile` 完全失效、译文的权威存储是缓存文件而非产物。

**每加一个源、一个字段、一个渲染分支，都在赌有没有人记得同步白名单。**
这个体系在 6 个模块规模下已经出过至少 3 次事故（用户自述），
到 10 个模块会变成主要的 bug 来源。

**方向**：给"条目"一个显式类型（`TypedDict`/dataclass，见 P2-2）+
契约测试（枚举上游产出字段，断言全部有归属）。
白名单反转成黑名单，让"新字段默认通过"。

### 不撑不住、但值得现在就做的

- **CI 加测试门禁**（P1-21）：成本最低、收益最高的单项改进。当前公网部署零测试门禁。
- **接 ruff**（P1-22）：代码里已有一堆写给不存在的 linter 的 `# noqa`。
- **原子写**（P1-12）：局部改动，直接消掉一类"损坏文件"故障。
- **i18n 流式落盘**（P1-11）：直接省钱。
- **jsonl 压实**（P1-14）：`cards.jsonl` 79.2% 是死数据。

---

## 附录：本次评审已验证为"没问题"的项

为避免后续重复排查，记录几处**实测确认安全/正确**的地方：

| 项 | 结论 | 证据 |
|---|---|---|
| `feed.html` 是否含密钥 | **干净，可分发** | 7 次 `sk-` 告警全部是 `'sk-proof-loop'`（来自仓库名 `repo-ta`**`sk-proof-loop`**）；`feed["config"]` 不含密钥字段 |
| `i18n.py` 线程安全 | **无数据竞争** | `pool.map` 结果在主线程串行消费（`i18n.py:321`），`stats`/`new_rows`/`cache` 均只在主线程改 |
| 模块循环依赖 | **无** | 依赖图单向 |
| 测试是否依赖真实网络 | **不依赖** | 58 用例 1.5 秒跑完，全部 fixture + tempdir |
| f-string 花括号双写 | **当前无错误** | 700 对双写全部正确，仅 2 处单写 `{variant}` 是合法占位符 |
| SQL 注入 | **无** | `server/db.py` 全部参数化查询 |
| `xiaohongshu` 源的 `url` | **受约束** | `xiaohongshu.py:404` 用 `f"https://github.com/{fn2}"` 构造；`note_url` 被 `KEEP_KEYS` 丢弃 |
| 会话 Cookie 属性 | **配置正确** | `httponly=True` + `samesite="lax"` + https 时 `secure=True`（`server/auth.py:62-70`）；`samesite=lax` 也是当前 CORS 配置下的实际 CSRF 防线 |
| OAuth state 校验 | **有** | `server/app.py:98-100` 比对 cookie 中的 state |

---

## 附录：严重度汇总

**P0（上线公网前必须修，5 项）**

| ID | 摘要 | 位置 |
|---|---|---|
| P0-1 | `</script>` 断出内联 payload → 存储型 XSS（**已实测复现**） | `feed_dashboard.py:28,741` |
| P0-2 | `javascript:` 协议直达 `href`/`src`（**已实测复现**） | `feed_dashboard.py:1657,1674,1688,2126` |
| P0-3 | 会话密钥硬编码兜底 `"dev-only-change-me"`，启动无校验 | `server/config.py:22` |
| P0-4 | 产物无 CSP / 无任何安全头 | `feed_dashboard.py:32-41` |
| P0-5 | `gates.details` 455 条内部判定随页面公开 | `gates.py:78,142` |

**P1（真实正确性/健壮性风险，24 项）**

| ID | 摘要 | 位置 |
|---|---|---|
| P1-1 | `skillfeed.py` 979 行过载入口，`cmd_refresh` 单函数 294 行 | `skillfeed.py:312-605` |
| P1-2 | `KEEP_KEYS` 静默丢 22 字段；corpus 378 条永久缺英文标签 | `feed_pack.py:12-21,97` |
| P1-3 | 先分类→翻译→再分类；`build` 会吃掉已有译文 | `skillfeed.py:120-134,574-597` |
| P1-4 | `serve` 触发 rebuild + LLM 调用，有写副作用 | `skillfeed.py:867-869` |
| P1-5 | f-string 拼 2437 行，1400 次手工双写花括号 | `feed_dashboard.py:32-2437` |
| P1-6 | 探测无请求预算，单仓最坏 570 次请求 / 190 分钟 | `skill_detect.py:194-236` |
| P1-7 | `monorepo_expand_limit` 三处不一致，生效值 20 | `skill_detect.py:52` / `config_defaults.json:23` |
| P1-8 | `trending` 异常处理器内部抛未捕获异常，且上游无 try | `trending.py:253` / `skillfeed.py:353` |
| P1-9 | GitHub 403 误报成"限流"，已取回的 ratelimit 头未使用 | `github_search.py:182-184` |
| P1-10 | ~60 处静默失败；`_call_model` 失败原因塌缩且不记日志 | `i18n.py:226-237` 等 |
| P1-11 | 长流程无时间戳/无进度/不可续跑；i18n token 可白烧 | `i18n.py:339-340` |
| P1-12 | **全仓零原子写**（`os.replace` 出现 0 次） | 全仓 |
| P1-13 | 三个产物三次独立写，无一致性标记 | `skillfeed.py:596-597` |
| P1-14 | `cards.jsonl` 79.2% 死数据；`index.jsonl` 单轮解析 4+ 次 | `i18n.py:136-144` / `corpus.py:52-59` |
| P1-15 | **`gate_profile` 是死配置**，三个 profile 结果相同 | `gates.py:33-34` / `config_defaults.json:2-3` |
| P1-16 | 3 处影子默认值 | `skillfeed.py:337,414,463` |
| P1-17 | 四层配置优先级不一致；`DASHSCOPE_BASE_URL` 反向 | `i18n.py:268` |
| P1-18 | 覆盖率盲区：转义/`i18n`/`skill_detect` 探测/错误路径 | `tests/` |
| P1-19 | 脆弱测试：单用例 28 处断言模板源码字符串 | `tests/test_feed_dashboard.py:182-209` |
| P1-20 | node 缺失时静默跳过全部行为测试，CI 无 node | `tests/test_feed_dashboard.py:246` |
| P1-21 | **CI 完全不跑测试** | `.github/workflows/pages.yml` |
| P1-22 | **零 linter/formatter/typechecker 配置**，却散布 `# noqa` | 全仓 |
| P1-23 | 无 `requirements.txt`；服务端依赖未锁版本；Py 版本不一致 | `requirements-server.txt` |
| P1-24 | 8 处性能陷阱（重复 IO / 每请求 1.5 MB / 无连接池） | 见 P1-24 |

**P2（可维护性，3 项）**：属性插值未统一转义（`feed_dashboard.py` 29 处）、
类型标注精度低（管线 item 是裸 `dict`）、11 处重复 argv 解析 + 遗留临时文件。

---

*评审人：Code Reviewer · 快照 2026-09-03 16:46–17:00 (UTC+8) · 基线 `10465b8` + 未提交改动*
*本次评审未修改任何生产代码；临时分析脚本已删除。*
