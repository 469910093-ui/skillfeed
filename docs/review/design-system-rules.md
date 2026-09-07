# skill-feed 设计系统现状梳理（只读盘点）

> **用途**：为后续接入 Figma（Model Context Protocol）做准备的现状基线。
> **性质**：只读分析，未修改任何源码。本文件是本次工作的唯一产出。

---

## 0. 读取时间点与并发提示

| 项 | 值 |
|---|---|
| 读取时间 | **2026-09-03 16:44 – 17:05 (UTC+8)** |
| 仓库 | `D:\Users\yaowenliang\Projects\skill-feed` |
| HEAD | `10465b8` — *Fix Feeds keywords: real lexicon only, no Chinese sliding fragments.* (2026-08-11) |
| 工作区状态 | 15 个文件 modified、9 个 untracked（含 `i18n.py`、`bitable_store.py`）——**未提交的改动已计入本次分析** |
| 相邻仓库 | `D:\Users\yaowenliang\Projects\skill-picker`（第二套前端，见 §7.2） |

**并发警告**：分析期间有三个 agent 在改代码。`feed_dashboard.py` 在我读取过程中就从 2437 行涨到 **2622 行**（`~/.skill-feed/feed_dashboard.py` 镜像时间戳 16:43:45，`i18n.py` 16:34:00，`skillfeed.py` 16:40:20）。**本文所有行号以 2026-09-03 17:00 时刻的 2622 行版本为准**，后续引用请先 `git diff` 校对偏移。

**文件结构基线**（`feed_dashboard.py`，2622 行）：

| 区段 | 行范围 | 行数 |
|---|---|---|
| Python 函数头 + 变体解析 | 1–31 | 31 |
| HTML `<head>` + 字体引入 | 32–40 | 9 |
| **内联 CSS**（`<style>`…`</style>`） | **41–645** | **603** |
| HTML 骨架（`<body>`） | 646–739 | 94 |
| **内联 JS**（`<script>`…`</script>`） | **740–2607** | **1866** |
| 收尾 + Python 写盘函数 | 2608–2622 | 15 |

---

## 1. 设计令牌（Design Tokens）

### 1.1 唯一的令牌定义点

> **注意：下面这份令牌快照已过期。** 本文是审计报告，保留审计当时的原样以便对照，
> 不随代码更新。品牌令牌（`--like` / `--link` / `--ring` / `--logo`）后来因为
> Instagram trade dress 风险已整组替换，`--muted` 也已因对比度改为 `#737373`。
> **当前生效的值看 [`docs/brand-tokens.md`](../brand-tokens.md)。**

全库只有一处 CSS 变量声明，写在 Python f-string 字面量里：

```42:54:feed_dashboard.py
  :root {{
    --bg: #fafafa;
    --ink: #262626;
    --muted: #8e8e8e;
    --line: #dbdbdb;
    --card: #ffffff;
    --like: #ed4956;
    --link: #00376b;
    --ring: linear-gradient(45deg, #f09433 0%, #e6683c 25%, #dc2743 50%, #cc2366 75%, #bc1888 100%);
    --font: "Outfit", "PingFang SC", "Microsoft YaHei", sans-serif;
    --logo: "Cookie", "Billabong", cursive;
    --phone: 470px;
  }}
```

**共 11 个令牌**：8 个颜色（含 1 个渐变）、2 个字体栈、1 个布局宽度。

### 1.2 令牌覆盖的维度（以及缺的）

| 维度 | 有令牌？ | 现状 |
|---|---|---|
| 颜色 | 部分 | 7 个语义色 + 1 渐变；缺 success/warning/info、缺表层（surface）分级、缺边框态（hover/focus） |
| 字体族 | 有 | `--font` / `--logo` |
| **字号** | **无** | 全部散落硬编码，且混用 `rem` 小数（`.62rem`、`.66rem`、`.68rem`、`.72rem`、`.75rem`、`.76rem`、`.78rem`、`.8rem`、`.82rem`、`.85rem`、`.86rem`、`.88rem`、`.9rem`、`.92rem`、`.95rem`、`1.05rem`、`1.1rem`、`1.2rem`、`1.25rem`、`1.35rem`、`1.45rem`、`2rem`）——**22 级字阶，无一个是令牌** |
| **字重** | **无** | `500/600/650/700/800` 混用，其中 `.pitch .problem` 用了非常规的 `650`（`:297`） |
| **间距** | **无** | `padding`/`gap`/`margin` 全硬编码：2/4/5/6/7/8/9/10/12/14/16/18/22/28px 等 14 种以上取值 |
| **圆角** | **无** | `6px / 8px / 10px / 12px / 14px / 16px / 18px / 50% / 999px` 共 9 种，无令牌 |
| **阴影** | **无** | 5 处 `box-shadow` / `drop-shadow`，各自独立，如 `0 12px 36px rgba(0,0,0,.28)`（`:575`）、`0 8px 24px rgba(0,0,0,.25)`（`:616`） |
| **层级 z-index** | **无** | `2 / 3 / 40 / 50 / 60 / 80 / 90 / 100` 硬编码，无 scale |
| **动效时长** | **无** | `.1s / .15s / .2s / .35s / .45s / .7s / 1.2s / 3.5s` 散落；`STORY_MS = 3500`（`:747`）与 CSS `svFill 3.5s`（`:532`）是**两处手工同步的魔法数** |
| 断点 | 事实上只有 1 个 | 见 §6.2 |

### 1.3 组织格式与转换体系

- **格式**：无。令牌不是 JSON/YAML/TS，是 Python 源码里的字符串片段。
- **转换体系**：**完全没有**。没有 `tokens.json`、没有 style-dictionary、没有 Tailwind config、没有 CSS 预处理器、没有任何构建管道（详见 §3）。
- **消费方**：只有 `feed_dashboard.py` 自己。`server/templates/*.html` 和 `docs/ui-skeleton.html` 各自重新定义了一套变量（§6.1）。

### 1.4 硬编码散落情况（量化）

CSS 区（`:41-645`）内 hex 色出现频次统计：

| 频次 | 值 | 问题 |
|---|---|---|
| **37** | `#fff` | 已有 `--card: #ffffff`（`:47`），但 `var(--card)` **只被用了 5 次**。白色 87% 走硬编码 |
| 4 | `#efefef` | 完全未令牌化：`body` 背景（`:56`）、`.search` 背景（`:122`）、`.pub-actions button.following`（`:349`）、`.sheet-close`（`:384`） |
| 3 | `#0d1117` | GitHub 深色，`.media` / `.media .cover` 底色（`:249`、`:256`、`:262`） |
| 3 | `#24292f` | GitHub 文字色（`:262`、`:311`、`:321`） |
| **2** | `#262626` | **与 `--ink` 值完全相同**，重复定义（`:279`、`:483/504` 的 `rgba(38,38,38,.92)` 也是同一个色的 rgba 写法） |
| **2** | `#dbdbdb` | **与 `--line` 值完全相同**，重复定义（`:169` `.story .ring`；`--line` 在 `:46`） |
| 1 each | `#111`（`:514`）、`#e8e8e8`（`:172`）、`#f5f5f5`（`:183`）、`#c7c7c7`（`:126`）、`#f6f8fa`（`:310`）、`#eaeef2`（`:310`） | 灰阶完全无体系，6 个孤立灰值 |
| 1 each | `#7c3aed` / `#db2777` / `#f59e0b`（`:554`） | Story 默认渐变，三个 Tailwind 调色板色，与其他体系无关 |

令牌使用频次（`var(--x)` 在 CSS 区）：

```
--ink  → 32    --muted → 23    --line → 19    --like → 9
--card →  5    --phone →  5    --bg   →  3    --ring → 3
--font →  1    --logo  →  1    --link → 1
```

**结论**：`--ink` / `--muted` / `--line` 用得不错；`--card` / `--link` 基本形同虚设；`#fff`、`#efefef` 是最大的两个"影子令牌"。

### 1.5 第二套颜色系统：JS 侧调色板

CSS 之外还有一套**运行时派生**的颜色，不在任何令牌里：

```865:874:feed_dashboard.py
const PALETTES = [
  ['#ff6a3d','#c32bad','#7028e4'],
  ['#00c6ff','#0072ff','#7b2ff7'],
  ['#f7971e','#ffd200','#f53844'],
  ['#11998e','#38ef7d','#0f766e'],
  ['#ee0979','#ff6a00','#f9d423'],
  ['#396afc','#2948ff','#00d2ff'],
  ['#232526','#414345','#757F9A'],
  ['#fc466b','#3f5efb','#00f2fe'],
];
```

24 个 hex，通过 `hashHue()` + `paletteFor()`（`:994-1002`）按 `owner` / `scene` 字符串哈希取色，用于头像底色（`:1649`）、Story 圆环（`:1830-1833`）、Story 全屏渐变（`sceneGradient` `:2082-2086`）。

这意味着 **一个具体卡片的头像颜色不可在设计稿中指定**，只能定义"这 8 组渐变是合法调色板"。`#0f766e` 在这里出现，也正是 `docs/ui-skeleton.html` 的 `--accent`（`:14`）——但两者毫无关联，纯属巧合。

---

## 2. 组件库

### 2.1 组件在哪里

没有组件库。UI 被切成两类"事实组件"：

**（A）静态骨架 — HTML 字面量，`:646-739`**（约 94 行）
`topbar` / `lite-banner` / `search-wrap` / `stories-wrap` / 三条 `filter-strip` / `bottom` 导航 / `story-viewer` / `demo-bar` / `toast` / `sheet`。这些是**单例**，写死在模板里，没有函数封装。

**（B）动态渲染 — JS 模板字符串函数**

| "组件" | 函数 | 行范围 | 规模 |
|---|---|---|---|
| Feed 卡片 | `cardHtml(it, idx)` | `:1614-1690` | **77 行单函数返回一整块 HTML** |
| 发布者主页 | `publisherPanelHtml(owner, ghRepos)` | `:1727-1774` | 48 行 |
| 我的页 | `mePanelHtml()` | `:1902-1956` | 55 行 |
| 空态 | `emptyHtml(items)` | `:1873-1900` | 28 行 |
| Stories 圆环 | `renderStories()` | `:1791-1839` | 49 行 |
| 筛选 pills | `renderPills(el, items, key, show)` | `:1848-1854` | 7 行（**唯一真正可复用的**） |
| 关注浮层 | `openFollowSheet(kind)` / `openIndustrySheet(id)` | `:1164-1222` | 59 行 |
| Story 幻灯页 | `renderSvSlide()` | `:2088-2133` | 46 行 |
| 图标 | `heartSvg(filled)` / `bookmarkSvg(filled)` | `:1541-1549` | 见 §5 |

### 2.2 组件架构与复用边界

**架构 = 字符串拼接 + CSS class 门控**。没有 props 契约、没有 slot、没有变体枚举。

卡片的"变体"是通过在 class 属性里拼三元运算符实现的：

```1628:1642:feed_dashboard.py
  const softCls = it.soft ? ' soft' : '';
  const noCoverCls = cover ? '' : ' no-cover';
  const focus = demo.focus === idx ? 'focus' : '';
  ...
  const bareCoverCls = (coverTitle || coverDesc) ? '' : ' bare';
  return `<article class="post ${{it.from_corpus ? 'corpus' : ''}}${{softCls}} ${{focus}}" id="post-${{idx}}"
```

即卡片实际有 **`corpus` × `soft` × `no-cover` × `bare` × `focus` 共 5 个正交布尔维度**（理论 32 种组合），但没有任何地方把它们枚举出来。这是 Figma component set 映射时最难对齐的地方（§8.3）。

**复用边界评估**：

- ✅ `renderPills` 是唯一带参数、被 3 处复用的真组件（`:1980-1982`）。
- ⚠️ `heartSvg` / `bookmarkSvg` 是"图标组件"，但 filled/outline 靠两条完整 SVG 硬编码切换。
- ❌ `.pub-actions a/button` 与 `.me-actions a/button` 是**同一个按钮组件被复制了两份 CSS**（`:341-348` vs `:471-478`，规则逐字相同）。
- ❌ 卡片、Story、Sheet 各自独立，共享的只有 CSS class 名。
- ❌ 大量元素直接内联 `style=`（15 处，`:1175`、`:1190`、`:1649`、`:1740`、`:1743`、`:1745`、`:1747`、`:1756`、`:1760`、`:1833`、`:1891-1896`、`:1912`、`:1915`、`:1921`、`:1928`）绕过 CSS 层。

### 2.3 组件文档 / Storybook

**都没有。** 与之最接近的是：

- `docs/ui-skeleton.html`（295 行）——一份**独立视觉体系**的手写静态原型（§6.1），实际未被代码引用，属于历史设计稿。
- `docs/PRD.md`（363 行）——只有交互与信息架构表格（如 `:249-253` Stories 圆环规格），无视觉规格、无令牌表、无组件清单。
- `tests/test_feed_dashboard.py`（344 行）——实质上是"通过断言字面量描述 UI"的伪文档（见 §8.4）。

---

## 3. 框架与依赖

### 3.1 前端框架

**零依赖，零框架。** 全库无 `package.json`、无 `node_modules`、无任何 `import`/`<script src>` 指向第三方 JS。

唯一的外部资源是 Google Fonts：

```38:40:feed_dashboard.py
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Billabong&family=Cookie&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
```

原生 JS 用到的能力：`localStorage`、`fetch`、事件委托、`URLSearchParams`、`IntersectionObserver` 的替代（scroll + `getBoundingClientRect`，`:2018-2027`）。全部手写。

`node` 只出现在测试里，且是可选依赖：

```12:12:tests/test_feed_dashboard.py
NODE = shutil.which("node")
```

### 3.2 后端与其他依赖

- `server/` — FastAPI + SQLite（`requirements-server.txt` 仅 4 行）。模板是手写 HTML 字符串/文件（`server/templates/home.html`、`publish.html`），非 Jinja 组件化。
- 主 CLI `skillfeed.py` 只用标准库 + 本地模块。
- `i18n.py` 走阿里云百炼（DashScope）生成双语文案，**只产出文本数据，不参与样式**。

### 3.3 样式方案

**单一内联 `<style>` 块，全局作用域，纯手写 CSS。** 无 CSS-in-JS、无 CSS Modules、无 BEM 工具、无 PostCSS/Sass/Less、无 utility framework。

### 3.4 构建系统与打包器

**不存在。** "构建"就是 Python 执行 f-string 插值后写文件：

```2613:2621:feed_dashboard.py
def write_feed_html(feed: dict, path: Path, *, variant: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_feed_html(feed, variant=variant), encoding="utf-8")


def write_feed_variants(feed: dict, *, full_path: Path, lite_path: Path) -> None:
    """同时写出独立站 full 页与 picker 用 lite 页。"""
    write_feed_html(feed, full_path, variant="full")
    write_feed_html(feed, lite_path, variant="lite")
```

CI（`.github/workflows/pages.yml`）只有 `setup-python@v5`，**没有 Node step**：

```98:110:.github/workflows/pages.yml
      - name: Refresh feed
        ...
        run: |
          python skillfeed.py refresh --force
          python skillfeed.py publish-site --out site
```

### 3.5 f-string 花括号双写（对后续所有工具化的硬约束）

因为整个 CSS+JS 都在一个 Python f-string 里，**每个 CSS 规则块和每个 JS 代码块的花括号都必须双写**：

```55:57:feed_dashboard.py
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; background: #efefef; color: var(--ink); font-family: var(--font); }}
  body {{ min-height: 100vh; }}
```

后果：这个文件对所有前端工具链（Prettier / Stylelint / ESLint / PostCSS / Figma MCP 代码生成）**都不是可解析的输入**，也不是可直接写入的输出。详见 §8.2。

---

## 4. 资源管理

### 4.1 图片资源

**零本地静态资源。** 仓库里没有 `assets/`、`static/`、`public/` 目录，一张图片都没有（`skill-picker` 有 `docs/assets/*.png`，本仓没有）。

所有卡片封面来自 **GitHub 的 OpenGraph 服务**，服务端拼 URL：

```32:37:feed_pack.py
def cover_url_for(full_name: str) -> str:
    """GitHub 仓库社交预览图（真实封面，非纯色占位）。"""
    fn = (full_name or "").strip()
    if "/" not in fn:
        return ""
    return f"https://opengraph.githubassets.com/1/{fn}"
```

写入 payload（`feed_pack.py:78`）：`out["cover_url"] = out.get("cover_url") or cover_url_for(fn)`
UGC 侧同源（`server/ugc.py:77`、`:110`），DB 有列（`server/db.py:33` `cover_url TEXT`）。

前端消费 + 兜底链路（`cardHtml`）：

```1657:1661:feed_dashboard.py
      ${{cover ? `<img class="cover" src="${{escapeHtml(cover)}}" alt="${{escapeHtml(headName)}}" loading="lazy" referrerpolicy="no-referrer" onerror="this.closest('.media').classList.add('no-cover')" />` : ''}}
      ${{(coverTitle || coverDesc) ? `<div class="cover-fallback">
        ${{coverTitle ? `<div class="t">${{escapeHtml(coverTitle)}}</div>` : ''}}
        ${{coverDesc ? `<div class="d">${{escapeHtml(coverDesc)}}</div>` : ''}}
      </div>` : ''}}
```

三级降级：**真 OG 图 → `onerror` 加 `.no-cover` 显示文字兜底层 → 文字与正文重复时加 `.bare` 缩成 46px 窄条**（`:266`）。

### 4.2 视频资源

无。Story viewer 是纯 CSS 渐变 + 静态图 + `svFill` 进度条动画（`:520-533`），不涉及视频。

### 4.3 优化手段（现有的）

| 手段 | 位置 | 备注 |
|---|---|---|
| `loading="lazy"` | `:720`、`:1657` | 2 处 |
| `referrerpolicy="no-referrer"` | `:720`、`:1657` | 隐私/防盗链 |
| `aspect-ratio: 2 / 1` + `object-fit: contain` | `:245`、`:254`、`:579-580` | 防 OG 图裁切（PRD `:411` 明确的决策） |
| 分页渲染 | `PAGE = 6`（`:746`）+ `maybeLoadMore()`（`:2018`） | 每次只渲染 6 张卡 |
| `preconnect` 字体域 | `:38-39` | |
| payload 瘦身 | `feed_pack.py:12-21` `KEEP_KEYS`、`BODY_PREVIEW_MAX = 700` | |

**未做的**：无 `srcset`/`sizes`、无 WebP/AVIF 协商、无图片尺寸声明（`width`/`height` 缺失 → CLS 风险，靠 `aspect-ratio` 部分缓解）、无 `fetchpriority`、无 service worker、无字体 `font-display` 之外的优化。

### 4.4 CDN 配置

**完全没有 CDN 配置。** 全库检索 `CDN` / `OSS` / `aliyun` / `jsdelivr` / `unpkg` 的结果只有：

- `config_defaults.json:29` — `"i18n_base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1"`（**LLM API，不是资源 CDN**）
- `i18n.py:27`、`.env.example:12-17`、`README.md:73/95` — 同上，阿里云百炼文案生成
- `小红书搜集/*.csv` 里的 `sns-webpic-qc.xhscdn.com` — 采集来的小红书图床 URL，**只是数据，未在前端渲染**

**国内访问风险清单**（针对阿里云 + ICP 备案上线）：

| 依赖 | 域名 | 国内可达性 | 影响 |
|---|---|---|---|
| Web 字体 | `fonts.googleapis.com` / `fonts.gstatic.com` | ❌ 基本不可达 | Outfit / Cookie / Billabong 全部失效，回落到 `PingFang SC` / `Microsoft YaHei` / `cursive`。**Logo（`--logo`，`:78-87`）视觉完全变形** |
| 卡片封面 | `opengraph.githubassets.com` | ⚠️ 不稳定 | 大面积走 `.no-cover` 兜底 → Feed 变成纯文字流，视觉完全不同 |
| 发布者仓库列表 | `api.github.com`（`:1701`） | ⚠️ 不稳定 | 发布者页降级为"暂无更多公开仓库" |
| 唯一 CTA 目标 | `github.com` | ⚠️ 不稳定 | 产品核心动作受影响（属产品风险，非样式） |

**这意味着国内线上的实际视觉 ≠ 本地/Pages 的视觉。** Figma 稿必须按"字体已回落 + 封面大量缺失"的降级态来做，否则设计稿永远无法在国内被还原（§8.8）。

---

## 5. 图标体系

### 5.1 现状：全部手写内联 SVG path

**是的，确认是手写内联 SVG。** 全库共 **10 个 `<svg>`**，全部在 `feed_dashboard.py`，全部是手写 `path`/`polygon`/`circle`：

| # | 图标语义 | 位置 | 形态 |
|---|---|---|---|
| 1 | 播放（自动 Demo） | `:660` | `<polygon points="6,4 20,12 6,20"/>` |
| 2 | 心形描边（顶栏反馈按钮） | `:664` | `<path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0…"/>` |
| 3 | 房子（发现 tab） | `:694` | `<path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z"/>` |
| 4 | 加号（发布 tab） | `:698` | 两条 `path` |
| 5 | 人像（我的 tab） | `:702` | `circle` + `path` |
| 6 | **心形实心** | `:1542` | `heartSvg(true)` |
| 7 | **心形描边** | `:1543` | `heartSvg(false)` — **与 #2 的 path 逐字重复** |
| 8 | 书签实心 | `:1547` | `bookmarkSvg(true)` |
| 9 | 书签描边 | `:1548` | `bookmarkSvg(false)` — **与 #8 的 path 逐字相同，仅 fill/stroke 不同** |
| 10 | 拇指朝下（不感兴趣） | `:1680` | `<path d="M10 15v4a3 3 0 0 0 3 3l4-9V2H5.72…"/>` |

补充：还有 1 处 CSS 生成的伪图标 —— 亮点列表的星形是 `content: "✦"`（`:314`），以及 Story 引导环用文本 `'+'`、关注总环用文本 `'★'`（`:1826-1827`、`:1807`）。也就是说**图标体系里混了 SVG、Unicode 字符、纯文本三种实现**。

### 5.2 存储方式

无图标目录、无 sprite sheet、无 icon font、无 SVG symbol、无组件库（Lucide/Feather/Heroicons 均未引入）。虽然多数 path 明显源自 Feather Icons 的 24×24 网格（`viewBox="0 0 24 24"`、`stroke-width="1.8"`），但**没有任何出处标注**。

### 5.3 命名约定

**没有图标命名体系。** 只有两个函数名带语义（`heartSvg`、`bookmarkSvg`），其余 8 个 SVG 是匿名的、直接嵌在 HTML 里。

尺寸约定散落在三处 CSS，各不相同：

```98:98:feed_dashboard.py
  .icon-btn svg {{ width: 24px; height: 24px; }}
```
```415:415:feed_dashboard.py
  .act svg {{ width: 26px; height: 26px; }}
```
```459:459:feed_dashboard.py
  .nav svg {{ width: 24px; height: 24px; }}
```

即 **24 / 26 两种尺寸，无 icon size token**；`.heart-burst` 又用 90px（`:281`）。

### 5.4 对 Figma 的含义

Figma 侧要建图标 library 时，**代码侧没有可对齐的锚点**：既没有 `icon/heart-filled` 这样的名字，也没有统一网格与描边规范（`stroke-width` 有 `1.8` 一种，但 fill 版本没有描边）。这是接入 Figma 后**最容易也最值得先标准化**的一层（成本最低、风险最小，见 §8.9）。

---

## 6. 样式方法论

### 6.1 CSS 方法论

**无正式方法论。** 事实上的做法是"**语义化单类名 + 状态修饰类 + 后代选择器**"，接近松散的 BEM-lite：

- 块：`.post` / `.media` / `.pitch` / `.actions` / `.story` / `.sheet` / `.sv-*`
- 元素：靠后代选择器，不用 `__`：`.pitch .problem`、`.media .badge`、`.who .name`
- 修饰：靠独立状态类，不用 `--`：`.on` / `.show` / `.open` / `.hidden` / `.liked` / `.saved` / `.focus` / `.hot` / `.done` / `.active` / `.go` / `.flash` / `.bare` / `.no-cover` / `.corpus` / `.soft` / `.primary` / `.guide` / `.clickable`

统计（CSS 区 `:41-645`）：**126 个唯一类选择器**、102 处 `var(--*)`、5 个 `@keyframes`（`hintFlash` `:154`、`postIn` `:214`、`burst` `:286`、`pulse` `:493`、`svFill` `:533`）、**1 个媒体查询**。

**全局样式**：有，且是唯一作用域。

```55:57:feed_dashboard.py
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; background: #efefef; color: var(--ink); font-family: var(--font); }}
  body {{ min-height: 100vh; }}
```

无 CSS reset/normalize（只有 `box-sizing` 和 `margin: 0`）。所有类名在同一个全局命名空间，**没有隔离机制**——`discover.html` 被 skill-picker 用 iframe 嵌入（§7.2），iframe 是唯一的样式隔离手段。

有一处 `!important`（`:183`）和一处 `[hidden]` 兜底（`:131`），是典型的优先级救火痕迹。

### 6.2 响应式实现

**移动优先的固定宽度容器 + 唯一断点。**

主布局不靠断点，靠 `--phone` 令牌把整个应用锁在一个"手机壳"里：

```59:67:feed_dashboard.py
  .shell {{
    max-width: var(--phone);
    margin: 0 auto;
    min-height: 100vh;
    background: var(--bg);
    border-left: 1px solid var(--line);
    border-right: 1px solid var(--line);
    position: relative;
  }}
```

`--phone: 470px` 还被 `.sheet-panel`（`:364`）、`.story-viewer`（`:515`）、`.demo-bar`（`:485`）、`.toast`（`:507`）复用。

**全库唯一的媒体查询**：

```641:644:feed_dashboard.py
  @media (max-width: 520px) {{
    .shell {{ border: 0; }}
    .story-viewer {{ max-width: 100%; left: 0; transform: none; }}
  }}
```

断点定义在**内联字面量里，不是令牌**，且 `520px` 与 `--phone: 470px` 之间的 50px 关系没有任何注释说明（推测是 470 + 2×25 边距）。

其他响应式手段：`env(safe-area-inset-bottom)`（`:365`、`:450`、`:610`）、`min()` / `max-content` / `calc()`、`aspect-ratio`、`flex-wrap`、`grid-auto` 无（没用到 `auto-fill`，那是 skill-picker 的做法）。

**桌面端没有任何适配**：>520px 时就是一根 470px 宽的居中长条，两侧留白。这是刻意的产品决策（抖音式竖流），但意味着 Figma 只需要一个 470px 画板 + 一个 <520px 的溢出态。

### 6.3 暗色模式

**完全没有。** 全库检索 `prefers-color-scheme` / `color-scheme` / `dark` → **0 命中**（`feed_dashboard.py` 内 0 处）。

值得注意的反差：**相邻的 skill-picker 看板是纯暗色的**（`skill-picker/dashboard.py:78-80`，`--bg: #0e1013`）。所以在 skill-picker 的「去 GitHub 发现」tab 里，暗色看板套着一个亮色 iframe，视觉断裂由 `.discover-frame-wrap { background: #efefef; }`（`skill-picker/dashboard.py:115-118`）勉强收边。

局部"深色区域"是靠硬编码实现的，不是主题：`.media` 背景 `#0d1117`（`:249`）、`.story-viewer` 背景 `#111`（`:514`）、`.toast` / `.demo-bar` `rgba(38,38,38,.92)`（`:483`、`:504`）。

---

## 7. 项目结构

### 7.1 skill-feed 组织方式

**扁平的"一模块一职责"根目录 Python 包**，无 `src/`、无分层目录：

```
skill-feed/
├── skillfeed.py                 # CLI 总入口（978 行）：corpus/refresh/build/publish-site/serve/api/check/feedback/i18n/xhs-crawl
├── feed_dashboard.py            # ★ 唯一前端：整页 HTML/CSS/JS（2622 行）
├── feed_pack.py                 # payload 组装、瘦身、cover_url/skill_url 生成
├── i18n.py           [untracked]# 双语卡片文案（DashScope），只产文本
├── scene.py                     # 场景分类树（一级/二级 chips）
├── rank.py / gates.py / highlights.py / skill_detect.py   # 排序 / 门禁 / 亮点抽取 / SKILL.md 探测
├── corpus.py                    # 本地知识库（只增不删）
├── trending.py / hellogithub.py / github_search.py / catalog_sources.py / xiaohongshu.py   # 5 个数据源
├── feedback.py                  # 反馈聚合
├── bitable_store.py  [untracked]# 飞书多维表格
├── server/                      # FastAPI + SQLite
│   ├── app.py / auth.py / ugc.py / db.py / config.py
│   └── templates/{home,publish}.html    # ★ 第二、第三套视觉体系
├── scripts/                     # 一次性/运维脚本（导出、回填、小红书 loop）
├── tests/                       # unittest，含 node harness
├── docs/
│   ├── PRD.md                   # 产品真相源（AGENTS.md 强制同步）
│   ├── ui-skeleton.html         # ★ 第四套视觉体系（历史原型，未被引用）
│   └── product-corpus-and-taxonomy.md / hellogithub-*.{json,md} / implementation-plan-*.md
├── config_defaults.json         # 全部运行时参数
├── AGENTS.md / README.md
└── 小红书搜集/*.csv              # 采集原始数据（9 个 CSV，含 2 个 41KB 有效文件）
```

**功能组织模式**：
1. **数据源即模块** —— 每个发现源一个顶层 `.py`，接口统一（返回 repo dict 列表）。
2. **管道式 CLI** —— `refresh` = 源 → `skill_detect` → `gates` → `scene` → `rank` → `feed_pack` → `feed_dashboard`。
3. **单一 payload 契约** —— `feed_pack.KEEP_KEYS`（`feed_pack.py:12-21`）是前后端唯一接口，前端只认 `FEED` 这一个全局对象（`:741`）。
4. **PRD 强同步纪律** —— `AGENTS.md:52-64` 规定任何产品调优必须同批改 `docs/PRD.md` 并追加 §13 变更日志，"未回写 PRD 的产品改动视为未完成"。**注意：这条纪律目前只覆盖产品/交互，不覆盖视觉与令牌。**
5. **自复制部署** —— `self_copy()` 把工具拷到 `~/.skill-feed/`，与克隆目录解耦（该目录当前有 24 个 `.py` 镜像）。

### 7.2 双前端确认：是两套并存，且样式高度重复

**回答"是不是两套并存"：是，实际上是四套 CSS 体系、两个独立看板产品。**

**产品关系链路**：

```
skill-feed / feed_dashboard.py  ──build──>  ~/.skill-feed/feed.html       (variant=full, 2012 KB)
                                └─────────>  ~/.skill-feed/feed.lite.html  (variant=lite, 2012 KB)
                                                       │
                                        skill-picker/discover.py  ──copy──>  ~/.skill-picker/discover.html (737 KB)
                                                       │
skill-picker / dashboard.py     ──scan──>  ~/.skill-picker/dashboard.html (929 KB)
                                                       └── <iframe src="discover.html"> 内嵌 lite 页
```

关键代码：

```158:163:../skill-picker/discover.py
    # 1) 已有 skill-feed 构建好的 lite 页，直接拷贝
    lite = HOME / ".skill-feed" / "feed.lite.html"
    if lite.exists():
        shutil.copy2(lite, DISCOVER_HTML)
        return DISCOVER_HTML
```

```146:148:../skill-picker/discover.py
            import feed_dashboard  # type: ignore

            return feed_dashboard, root
```

```255:257:../skill-picker/dashboard.py
  <div class="discover-frame-wrap" id="discoverFrameWrap">
    <iframe id="discoverFrame" title="skill-feed lite" src="about:blank"></iframe>
  </div>
```

**四套视觉体系对照**（全部独立定义 `:root`，无共享）：

| # | 文件 | 令牌 | 字体 | 主色 | 底色 | 状态 |
|---|---|---|---|---|---|---|
| 1 | `feed_dashboard.py:42-54` | 11 个 | Outfit + Cookie/Billabong | `--like: #ed4956` | `#fafafa` 亮 | **生产**（full + lite 双变体） |
| 2 | `server/templates/home.html:9` | 4 个 | Outfit | `--accent: #db2777` | 三色渐变 | 生产（API 首页） |
| 3 | `server/templates/publish.html:9` | 5 个 | Outfit | `--accent: #db2777` | `#fafafa` | 生产（发布页） |
| 4 | `docs/ui-skeleton.html:9-18` | 8 个 | IBM Plex Sans (+ Condensed) | `--accent: #0f766e` | `#eceff3` + 双 radial | **死代码**（未被任何代码引用） |
| — | `../skill-picker/dashboard.py:78-80` | 13 个 | Microsoft YaHei / Segoe UI | `--blue: #60a5fa` | `#0e1013` **暗** | 生产（另一产品，同屏共存） |

**样式重复的具体证据**：

1. **`#db2777` 一色两名**：`server/templates/*.html` 叫 `--accent`；`feed_dashboard.py:554` 里同一个值是 Story 默认渐变的中间色，无名字。
2. **按钮组件在 #2/#3 之间复制**：`home.html:20-25` 的 `.btn` 与 `publish.html:20-25` 的 `.btn` 是两份**逐字相同**的声明。
3. **`--line` 三种值**：`#dbdbdb`（#1）、`#e5e7eb`（#2/#3）、`#d3dbe5`（#4）、`#262b33`（skill-picker）。同一语义四个值。
4. **`--muted` 四种值**：`#8e8e8e` / `#6b7280` / `#5c6b7a` / `#9aa3af`。
5. **`escapeHtml` 函数在两处独立实现**：`feed_dashboard.py:923-927` 与 `publish.html:134-136`。
6. **意图压缩算法在两仓重复实现**：`feed_dashboard.py:1255-1339`（JS `compressIntent`）与 `../skill-picker/discover.py:62-121`（Python `compress_intent_query`）——含**同一份词表**（`INTENT_PHRASES` vs `_PHRASES`）和同一个"产品设品设计"历史 bug 修补，两边必须手工同步。

`variant` 机制（唯一的正面例子）—— lite 与 full 共用一套 CSS，靠 body class 门控：

```624:639:feed_dashboard.py
  /* lite：skill-picker 发现子页 — 无 Stories/关注/发布/我的 */
  body.variant-lite .stories-wrap,
  body.variant-lite #followSheet,
  body.variant-lite .nav[data-action="publish"],
  body.variant-lite .nav[data-mode="me"],
  body.variant-lite .follow-mini,
  body.variant-lite #btnDemo {{ display: none !important; }}
  body.variant-lite .bottom {{ justify-content: center; }}
```

代价：lite 页**仍下发全部 CSS 与全部 payload**（feed.html 与 feed.lite.html 都是 2012 KB，一字节不差），只是用 CSS 藏起来。

---

## 8. Figma 接入的现实障碍与可行路径

### 8.1 结论先行

以当前架构，**Figma MCP 的标准工作流（`get_design_context` → 组件代码、Variables → tokens、Code Connect → 组件映射）三条链路全部落不了地**。原因不是"没有框架"（无框架也可以有令牌层），而是三个更底层的事实：

1. 令牌只有 11 个且大量被硬编码绕过（§1.4）——**Figma Variables 没有可写入的目标**；
2. 全部代码在 Python f-string 里、花括号双写——**没有任何工具可以读写这个文件**；
3. 组件是 77 行模板字符串、变体靠三元运算符——**Figma Component Set 没有可映射的对象**。

**能立刻做的是"设计令牌 + 图标"这两层；组件层需要先重构；全站高保真设计稿现在做出来会大幅领先代码，不建议。**

### 8.2 障碍一：f-string 花括号双写（最硬的一条）

```55:56:feed_dashboard.py
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; background: #efefef; color: var(--ink); font-family: var(--font); }}
```

- Figma MCP 生成的 CSS/JSX **不能直接粘贴**，每个 `{` `}` 都要先转义。手工转义 600 行 CSS 是纯错误源。
- 反向也不通：Stylelint / Prettier / PostCSS / 任何 CSS AST 工具**无法解析** `feed_dashboard.py`（它不是 CSS 文件）。所以"用工具检查令牌一致性"这条路现在是关闭的。
- JS 侧同样：`:1614-1690` 的 `cardHtml` 里嵌套着 `${{...}}` 三层模板字符串 + 三元表达式，人读都费劲，工具生成基本无望。

### 8.3 障碍二：无组件边界，变体不可枚举

Figma 的核心资产是 Component + Variant properties。代码侧对应物是：

```1643:1647:feed_dashboard.py
  return `<article class="post ${{it.from_corpus ? 'corpus' : ''}}${{softCls}} ${{focus}}" id="post-${{idx}}"
      data-fn="${{escapeHtml(fn)}}" data-src="${{escapeHtml(it.source || '')}}"
      data-scene="${{escapeHtml(sceneId)}}" data-l2="${{escapeHtml(it.scene_l2 || '')}}"
      data-owner="${{escapeHtml(owner)}}"
      data-fc="${{it.from_corpus ? '1' : '0'}}">
```

卡片有 5 个正交布尔（`corpus` / `soft` / `no-cover` / `bare` / `focus`）+ 3 个内容开关（`highlights` 有无、`who_for` 有无、`doc-link` 有无），**分散在 `cardHtml` 内部 20 多个三元表达式里，没有任何地方声明"这个组件有哪些变体"**。

后果：
- Figma 侧建 Component Set 时只能靠人肉阅读 `cardHtml` 反推变体矩阵，容易漏（比如 `.bare` 这种"文字去重后封面缩成 46px 窄条"的极端态，只有读 `:1638-1642` 的注释才能发现）。
- **Code Connect 做不了**。`.figma.ts` 需要 `import { Card } from '...'` 指向一个真实 export；这里没有 export，只有一个返回字符串的函数。

### 8.4 障碍三：测试把 HTML/CSS 字面量锁死了

`tests/test_feed_dashboard.py` 用 `assertIn` 断言具体样式与结构字符串：

```196:198:tests/test_feed_dashboard.py
        self.assertIn("sv-cover", html)
        self.assertIn("object-fit: contain", html)
        self.assertNotIn("background-size: cover; background-position: center;", html)
```
```240:243:tests/test_feed_dashboard.py
        self.assertIn(".media.no-cover.bare", html)
        # 亮点为空时整块不渲染，SKILL.md 链接只跟着真文档出
        self.assertIn("${hl ? `<ul class=\"highlights\">", html)
        self.assertIn("${hasSkillDoc(it) ? `<a class=\"doc-link\"", html)
```

更麻烦的是 node harness 的取码方式：

```17:18:tests/test_feed_dashboard.py
    blocks = re.findall(r"<script>(.*?)</script>", html, flags=re.S)
    return max(blocks, key=len)
```
```30:37:tests/test_feed_dashboard.py
        if re.match(r"^function\s+[A-Za-z0-9_$]+\s*\(", lines[i]):
            start = i
            i += 1
            while i < len(lines) and lines[i] != "}":
                i += 1
```

它依赖 **"顶层函数必须行首 `function` 开始、行首 `}` 结束"** 和 **"只有一个（最长的）`<script>` 块"**。

**代价量化**：一旦把 JS 拆成多个 `<script>`、或给函数加缩进（比如包进 IIFE/module）、或把 CSS 属性写法改一下，`TestCardDedupeJs` 下 6 个测试 + `TestFeedDashboard` 下 4 个断言会立刻红。这是重构成本里最容易被低估的部分。

### 8.5 障碍四：没有构建步骤，且"零构建"是产品约束而非技术债

产品形态要求 HTML 必须**自包含、可双击打开、可被 iframe 直接嵌**（`AGENTS.md:10-16` 双变体表、`skill-picker/discover.py` 的 copy 链路）。这不是偷懒，是分发决策。

因此"引入 npm + style-dictionary"不只是加个工具，而是**改变产品的分发契约**，还要连带处理：
- `.github/workflows/pages.yml` 只有 `setup-python@v5`（`:53-56`），需加 Node step；
- `skill-picker/discover.py:146` 直接 `import feed_dashboard` 跨仓库调 `build_feed_html()`——**如果 CSS 变成构建产物且不入库，这条链路就断了**，必须把产物 commit 进仓库。

### 8.6 障碍五：四套视觉体系并存

见 §7.2 表格。**现在建 Figma library，等于要决定"以哪一套为准"**。如果不先在代码侧收敛，Figma 里就会出现四个 library 或一个自相矛盾的 library，把不一致固化成设计资产。

### 8.7 障碍六：运行时派生色无法在设计稿中指定

`PALETTES`（`:865-874`）+ `hashHue()` 决定每个头像/圆环的具体颜色。设计师在 Figma 里画的头像颜色，**在代码里由 owner 名字的哈希决定**，无法指定。Figma 只能定义"这 8 组三色渐变是合法集合"，不能定义"stop-slop 的头像是紫色"。

### 8.8 障碍七：国内视觉 ≠ 设计稿视觉

`fonts.googleapis.com` 在国内不可达（§4.4）。设计稿里 Outfit 的字宽、Cookie 的手写 logo，在国内线上会变成 PingFang SC 和系统 `cursive`。**Logo 是品牌资产，`--logo: "Cookie", "Billabong", cursive`（`:52`）在国内会渲染成一个不可预测的系统手写体。**

同理 `opengraph.githubassets.com` 不稳定 → 卡片大面积走 `.no-cover` / `.bare` → Feed 视觉密度与设计稿完全不同。

**结论：Figma 稿必须先决定字体策略（自托管 woff2 上阿里云 OSS？还是改用系统字体栈？），否则设计稿不可还原。这个决策应该在画第一张稿之前做。**

### 8.9 可行路径（成本 / 风险 / 收益）

#### 路径 A：只抽令牌层 + 图标层 ★ 推荐立刻做

**做法**
1. 把 `:root` 从 f-string 提出成 `tokens.py`（或 `tokens.json` + `render_root_vars()`），补齐 spacing / radius / shadow / font-size / font-weight / z-index / duration / breakpoint 令牌。
2. 替换硬编码：37 处 `#fff` → `var(--card)`，4 处 `#efefef` → 新 `--surface-sunken`，2 处 `#262626` → `var(--ink)`，2 处 `#dbdbdb` → `var(--line)`，`#0d1117`/`#24292f`/`#f6f8fa`/`#eaeef2` → 新 `--gh-*` 令牌组。
3. 10 个内联 SVG 抽成 `ICONS = { 'heart-filled': '<path .../>' , ... }` 字典 + 一个 `icon(name, size)` 渲染函数，统一 24px 网格与 `stroke-width: 1.8`。
4. Figma 侧建 **Variables collection，命名与 CSS 变量 1:1**（`--ink` ↔ `color/ink`、`--phone` ↔ `size/phone-width`），建 **Icons library**（10 个 component，名字对齐 `ICONS` 的 key）。

**成本**：令牌 0.5–1 人日；图标 0.5 人日。**零新依赖，不动构建，不动 CI。**
**风险**：**低**。`tests/test_feed_dashboard.py` 的断言主要针对结构与文案，令牌替换不触发；但 `:197` 的 `assertIn("object-fit: contain")` 提醒——改属性**写法**（如换成简写）会红，改**值**不会。真正的风险是**与三个并发 agent 的合并冲突**，需排队或先只改 `:42-54` 这 13 行。
**收益**：Figma Variables / Icons 有了明确落点，改色改图标可机械同步。这是唯一"现在就能双向对齐"的层。

#### 路径 B：模板拆可复用片段

**做法**
1. 把 CSS 按块切成 `styles/_tokens.css`、`_card.css`、`_stories.css`… 用**普通字符串**读入拼接（`Path.read_text()`），**从此摆脱花括号双写**——这是本路径最大的隐性收益。
2. 把 `cardHtml` / `renderStories` / `mePanelHtml` / `emptyHtml` / `publisherPanelHtml` / `renderSvSlide` 拆成独立 `.js` 文件，同样以普通字符串读入。
3. 显式声明变体：`CARD_VARIANTS = ('corpus', 'soft', 'no-cover', 'bare', 'focus')`，并在文档里写清组合规则。
4. 合并重复：`.pub-actions` / `.me-actions` 按钮（`:341-348` vs `:471-478`）抽成一个 `.btn-pill`。

**成本**：2–4 人日。
**风险**：**中高，主要来自测试**。必须同批改 `tests/test_feed_dashboard.py` 的 `_script_source`（改成合并所有 script 块）和 `_top_level_functions`（改成能容忍缩进 / 多文件）。不改就是 10+ 测试全红。另外拆完后 CSS 拼接顺序决定优先级，`!important`（`:183`）和 `.variant-lite` 门控（`:624-639`，依赖出现在最后）**必须保证在最末尾**，否则 lite 页会漏出 Stories/发布/我的。
**收益**：有了真实的组件边界与文件锚点，Figma Component 可以一对一映射；Code Connect 勉强可做（指向片段文件）；且 CSS 变成合法 CSS 文件后，Stylelint / 令牌一致性检查工具全部解锁。

#### 路径 C：引入构建步骤（style-dictionary + esbuild/lightningcss）

**做法**：Figma Variables → `tokens.json` → style-dictionary → `dist/tokens.css`；JS/CSS 打包成 `dist/bundle.{css,js}`；Python 侧只做一次性内联注入。
**成本**：3–5 人日 + 长期维护（Node 版本、CI、lockfile）。
**风险**：**高**。①与"零依赖、双击可开"的分发契约冲突（§8.5）；②`pages.yml` 要加 Node；③`skill-picker/discover.py:146` 的跨仓 `import` 要求**构建产物必须 commit 进仓库**，否则链路断裂；④三个并发 agent 的工作流被打断。
**收益**：真正的令牌自动化，Figma 改色 → PR 自动生成。**建议在路径 A + B 稳定、且团队确认愿意接受 Node 依赖之后再评估。**

#### 路径 D：改用组件框架（React/Preact + Tailwind）

**成本**：重写整个前端，10+ 人日。
**风险**：**极高**。破坏三条现存分发链路（本地双击 `feed.html`、GitHub Pages `embed.html`、skill-picker iframe `discover.html`）；2 MB 内联 payload 变成需要 hydration 的负担；三个并发 agent 的改动全部作废；`variant=full/lite` 的 CSS 门控机制要重新设计。
**收益**：Figma MCP 全链路可用（`get_design_context` 直接产 JSX、Code Connect 完整）。
**何时值得**：只有当 skill-feed 从"本地工具产物"转型为"真 Web 产品（阿里云 + ICP + 登录 + UGC 混排）"、且愿意放弃单文件形态时。**现在不做。**

#### 推荐执行序

```
第 0 步（决策，0.5 天，无代码）
  ├─ 定字体策略：自托管 woff2 上 OSS？还是改系统字体栈？  ← 不定这个，Figma 稿不可还原
  └─ 定"以 feed_dashboard.py 为唯一真相源"，把 docs/ui-skeleton.html 标注废弃，
     server/templates/*.html 后续复用同一套令牌

第 1 步  路径 A（1–1.5 天，低风险）→ Figma 建 Variables + Icons library

第 2 步  Figma 只画"卡片 Component Set"一个高保真件（不画全站），
        与 §8.3 的 5 个布尔变体逐一对齐，验证令牌命名可用

第 3 步  评估路径 B（视第 2 步暴露的缺口决定拆到多细）

第 4 步  路径 C / D 暂不启动
```

**附加建议**：把 `AGENTS.md:52-64` 的 PRD 强同步纪律**扩展到视觉层**——新增一条"改令牌/改组件必须同批更新 `docs/review/design-system-rules.md` 或后续的 tokens 真相源"。否则四套体系的历史会重演。

---

## 9. 样式一致性问题清单

> 行号基于 2026-09-03 17:00 的 `feed_dashboard.py`（2622 行）。并发编辑中，引用前请 `git diff` 校对。
> 优先级：**P0** = 阻碍 Figma 接入 / 已造成用户可见不一致；**P1** = 明显技术债；**P2** = 整理项。

### 9.1 令牌缺失

| # | P | 问题 | 位置 |
|---|---|---|---|
| 1 | **P0** | **无间距令牌**：14+ 种 padding/gap/margin 取值散落 600 行 CSS | `feed_dashboard.py:41-645` 全域 |
| 2 | **P0** | **无字号令牌**：22 级 rem 小数字阶（`.62/.65/.66/.68/.72/.75/.76/.78/.8/.82/.85/.86/.88/.9/.92/.95/1.05/1.1/1.2/1.25/1.35/1.45/2` rem） | 全域，如 `:90`、`:108`、`:199`、`:297`、`:597` |
| 3 | **P0** | **无圆角令牌**：9 种取值 `6/8/10/12/14/16/18px + 50% + 999px` | `:302`、`:121`、`:372`、`:571`、`:364`、`:399`、`:169`、`:102` |
| 4 | **P0** | **无阴影令牌**：5 处各自独立 | `:283`、`:538`、`:575`、`:616` |
| 5 | P1 | **无 z-index scale**：`2/3/40/50/60/80/90/100` 硬编码 | `:70`、`:271`、`:282`、`:359`、`:447`、`:482`、`:506`、`:513`、`:522` |
| 6 | P1 | **无动效时长令牌**；且 `STORY_MS = 3500`（JS `:747`）与 `svFill 3.5s`（CSS `:532`）是两处手工同步的魔法数，改一处会静默失配 | `:532` + `:747` |
| 7 | P1 | **断点未令牌化**：`520px` 内联字面量，与 `--phone: 470px`（`:53`）的关系无注释 | `:641` |
| 8 | P1 | **无图标尺寸令牌**：`24px`（`:98`）/ `26px`（`:415`）/ `24px`（`:459`）/ `90px`（`:281`） | 见 §5.3 |
| 9 | P2 | 无 font-weight 令牌；出现非常规 `650` | `:297` |

### 9.2 硬编码绕过既有令牌

| # | P | 问题 | 位置 |
|---|---|---|---|
| 10 | **P0** | **`#fff` 硬编码 37 次，`var(--card)` 只用 5 次** —— 白色 87% 绕过令牌 | `:104,112,114,126,134,175,180,198,202,230,234,261,274,283,294,302,336,342,347,352,356,364,372,377,389,439,472,477,483,499,504,528,537,542,586,614,636` |
| 11 | **P0** | **`#262626` 重复定义 `--ink`**（值完全相同） | `:279`（另 `:483`、`:504` 的 `rgba(38,38,38,.92)` 同色 rgba 化） |
| 12 | **P0** | **`#dbdbdb` 重复定义 `--line`**（值完全相同） | `:169` |
| 13 | P1 | `#efefef` 出现 4 次却无令牌（body 底、search 底、following 态、sheet-close） | `:56`、`:122`、`:349`、`:384` |
| 14 | P1 | GitHub 品牌色系无令牌：`#0d1117`×3、`#24292f`×3、`#f6f8fa`、`#eaeef2` | `:249`、`:256`、`:262`、`:311`、`:321`、`:310` |
| 15 | P1 | 孤立灰阶 6 个，无体系：`#111`、`#c7c7c7`、`#e8e8e8`、`#f5f5f5` | `:514`、`:126`、`:172`、`:183` |
| 16 | P1 | Story 默认渐变三色 `#7c3aed / #db2777 / #f59e0b` 与全站色系无关（Tailwind 调色板色），且 `#db2777` 正是 `server/templates/*.html` 的 `--accent` —— **同一色两个名字、两个体系** | `:554` + `server/templates/home.html:9` + `publish.html:9` |
| 17 | P1 | `--link: #00376b` 定义后只用 1 次；`--font` / `--logo` 各只用 1 次（无二次消费点，等于把 fallback 栈锁死在单点） | `:49`+`:325`；`:51`+`:56`；`:52`+`:79` |
| 18 | P1 | **15 处内联 `style=` 绕过 CSS 层**，其中 `:1892-1893` 把整套按钮样式（padding/width/min-width/background/color/border）写进 HTML 属性 | `:1175,1190,1649,1740,1743,1745,1747,1756,1760,1833,1891,1892,1893,1895,1896,1912,1915,1921,1928` |
| 19 | P2 | `.pitch .highlights li::before { content: "✦" }` —— 用 Unicode 字符当图标，与 SVG 体系并行 | `:314` |
| 20 | P2 | Story 圆环用纯文本 `'+'` / `'★'` 当图标 | `:1807`、`:1826-1827` |

### 9.3 重复定义

| # | P | 问题 | 位置 |
|---|---|---|---|
| 21 | **P0** | **按钮组件 CSS 复制两份**，`.pub-actions a/button` 与 `.me-actions a/button` 规则**逐字相同**（含 `.primary` 变体） | `:341-348` **vs** `:471-478` |
| 22 | **P0** | **心形 SVG path 重复 3 次**（顶栏描边、`heartSvg(false)`、`heart-burst` 用 `heartSvg(true)`），其中 `:664` 与 `:1543` 的 path **逐字相同** | `:664`、`:1542`、`:1543` |
| 23 | P1 | 书签 SVG path 在 filled/outline 两个分支中**逐字相同**，只有 `fill`/`stroke` 属性不同 —— 应为一条 path + 属性切换 | `:1547-1548` |
| 24 | **P0** | **`--line` 同语义四个值**：`#dbdbdb` / `#e5e7eb` / `#d3dbe5` / `#262b33` | `:46`；`server/templates/home.html:9`；`docs/ui-skeleton.html:13`；`../skill-picker/dashboard.py:78` |
| 25 | **P0** | **`--muted` 同语义四个值**：`#8e8e8e` / `#6b7280` / `#5c6b7a` / `#9aa3af` | 同上四处 |
| 26 | **P0** | **`--ink` 同语义四个值**：`#262626` / `#1a1a1a` / `#0b1220` / `#e8eaed`（暗色反转） | 同上四处 |
| 27 | P1 | `escapeHtml()` 两处独立实现（逻辑相同，转义表写法不同） | `:923-927` **vs** `server/templates/publish.html:134-136` |
| 28 | P1 | **意图压缩算法跨仓重复**：JS `compressIntent` 与 Python `compress_intent_query` 各一份，含同一份词表与同一个"产品设品设计"历史 bug 修补 —— 必须手工双向同步 | `:1255-1339` **vs** `../skill-picker/discover.py:30-121` |
| 29 | P1 | `cover_url` 拼接逻辑在 Python 与 JS 各一份 | `feed_pack.py:32-37` **vs** `:1623` 与 `:2092`（**JS 内自身也重复一次**） |
| 30 | P2 | `docs/ui-skeleton.html`（295 行、完整第四套令牌体系）是死代码，无任何引用，却仍在 docs 里作为"设计参考"存在，会误导后续 Figma 工作 | `docs/ui-skeleton.html` 全文 |

### 9.4 命名不一致

| # | P | 问题 | 位置 |
|---|---|---|---|
| 31 | P1 | 主色语义在两套体系里叫法不同：`--like`（#1）vs `--accent`（#2/#3/#4） | `:48` vs `home.html:9` |
| 32 | P1 | 表层色命名混乱：`--bg` `--card` 与硬编码 `#efefef` 三层没有 surface 分级命名；skill-picker 那边是 `--panel` / `--panel2` | `:43,47,56` vs `../skill-picker/dashboard.py:78` |
| 33 | P1 | 修饰类命名无统一约定，同义状态多种写法：`.on` / `.active` / `.show` / `.open` / `.hot` / `.has-new` / `.go` / `.flash` / `.done` / `.liked` / `.saved` | `:112,202,1852`；`:495(.show)`、`:362(.open)`、`:171(.hot/.has-new)`、`:285(.go)`、`:151(.flash)`、`:531(.done)`、`:416` |
| 34 | P1 | 单字母类名 2 个（`.t` 封面大字、`.d` 封面描述），无语义、易冲突 | `:267`、`:268` |
| 35 | P2 | 前缀不统一：Story viewer 全用 `sv-` 前缀（17 个类），其他模块全无前缀（`.post` / `.pitch` / `.media`） | `:512-622` vs 其余 |
| 36 | P2 | "头像"三个类名指同一概念：`.avatar`（卡片）/ `.ava`（sheet + pub-head）/ `.face`（story） | `:224`、`:334`、`:375`、`:173` |
| 37 | P2 | `.lead` 在两处语义不同：sheet 说明文（`:369`）与 me-panel 说明文（`:463`），且被内联 style 反复覆盖（`:1740`、`:1743`、`:1745`） | `:369`、`:463` |
| 38 | P2 | JS 行为钩子用 `js-` 前缀（`js-like` / `js-media` / `js-publisher`…共 16 个），但**部分交互直接用语义类做钩子**（`.pill`、`.story`、`.nav`、`.post`），约定不彻底 | `:2302`、`:2288`、`:2367`、`:2494` |

### 9.5 结构 / 可访问性 / 主题

| # | P | 问题 | 位置 |
|---|---|---|---|
| 39 | **P0** | **无暗色模式**（全库 0 处 `prefers-color-scheme`），但 lite 页被嵌进纯暗色的 skill-picker 看板，靠 `.discover-frame-wrap{background:#efefef}` 硬性收边，视觉断裂 | `feed_dashboard.py` 全文 0 命中；`../skill-picker/dashboard.py:78`、`:115-118` |
| 40 | P1 | 无 `prefers-reduced-motion` 兜底，但有 5 个 keyframes 动画（含无限循环的 `pulse`） | `:154`、`:214`、`:286`、`:493`（infinite）、`:533` |
| 41 | P1 | `!important` 救火：`.story.guide .face i { background: #f5f5f5 !important }`，且同一元素背景又被内联 style 设置（`:1831-1833`）——两处打架 | `:183` + `:1831-1833` |
| 42 | P1 | `.intent-keys[hidden] { display: none !important }` 是为了压过前面的 `display: flex`，属优先级设计缺陷 | `:127-131` |
| 43 | P1 | `<img>` 无 `width`/`height` 属性，仅靠 `aspect-ratio` 兜 CLS；`.media.no-cover.bare` 还会**运行时改 aspect-ratio 为 auto**（`:266`），布局二次跳动 | `:1657`、`:720`、`:266` |
| 44 | P1 | 全站样式在同一全局命名空间，126 个类名无隔离；lite 页作为 iframe 内容时唯一隔离手段是 iframe 本身 | `:41-645` |
| 45 | P1 | lite 变体**下发全部 CSS + 全部 payload**（`feed.html` 与 `feed.lite.html` 均 2012 KB，字节数完全相同），仅用 CSS 隐藏 —— 嵌入场景白付 2 MB | `:624-639`；产物 `~/.skill-feed/feed.{,lite.}html` |
| 46 | P1 | 单文件 2 MB（payload 内联，`FEED = {payload}` at `:741`；`feed.json` 2169 KB → `feed.html` 2012 KB）。任何视觉复杂化都叠在这个基数上 | `:741` |
| 47 | P1 | **约 138 行 JS 含中文字面量绕过 `I18N` 表**（`:755-814`），EN 模式下会漏中文。典型：`openFollowSheet` 的「发现 Builder / 关注后… / 关闭」（`:1169-1195`）、`openIndustrySheet`（`:1207-1218`）、`mePanelHtml` 整块（`:1902-1956`）、`emptyHtml` 整块（`:1873-1899`）、`publisherPanelHtml`（`:1740-1772`）、`openStoryViewer` 的「关注动态」（`:2148`）、`followToast`（`:919`）、`renderIntentKeys` 的「已提炼 / 关键词」（`:1355-1357`）、`renderStories` 的「关注 / + Builder」（`:1807`、`:1826`）。**且 `openFollowSheet` 里靠比较中文字符串 `title === '发现行业'` 做分支（`:2344`）——切到 EN 后这个分支会静默失效** | 见左列 |
| 48 | P2 | HTML 骨架里也有硬编码中文（`更新 —`、lite banner、stories hint），靠 `applyLang()` 二次覆盖（`:2570-2573`）；首帧到语言切换之间会闪中文 | `:652`、`:669`、`:679` |
| 49 | P2 | `.sv-shade { display: none; }` 是死规则（无对应元素残留） | `:564` |
| 50 | P2 | `9.1#7` 的 `--phone: 470px` 被 5 处消费（`.shell` / `.sheet-panel` / `.story-viewer` / `.demo-bar` / `.toast`），是唯一被当真令牌用的尺寸；但同族的 `.sv-tap-left/right { width: 28% }`（`:619`）、`.sv-content p { max-height: 38vh }`（`:604`）等比例值仍是魔法数 | `:619`、`:604` |

### 9.6 需要产品/设计决策才能修的（不是纯技术债）

| # | 问题 | 依据 |
|---|---|---|
| 51 | **字体策略未定**：Google Fonts 国内不可达，Logo 会渲染成不可预测的系统 `cursive` | `:38-40`、`:52` |
| 52 | **封面来源单点**：`opengraph.githubassets.com` 不可达时 Feed 退化为纯文字流，设计稿需要同时定义"有封面/无封面/bare"三态的视觉密度 | `feed_pack.py:32-37`、`:1657`、`:266` |
| 53 | **头像/圆环色不可指定**（哈希派生），Figma 只能定义合法调色板集合 | `:865-874`、`:994-1002` |
| 54 | **四套视觉体系需先裁定真相源**，否则 Figma library 会固化不一致 | §7.2 表 |

---

## 附录 A：一页速查

| 问题 | 答案 |
|---|---|
| 令牌在哪 | `feed_dashboard.py:42-54`，11 个 CSS 变量，Python f-string 里 |
| 令牌格式 | 无格式，无转换体系，无 tokens.json |
| 组件在哪 | 9 个 JS 模板字符串函数 + 94 行 HTML 骨架；最大的 `cardHtml` 77 行 |
| 组件文档 | 无；无 Storybook |
| 框架 | 零依赖零框架，原生 JS + 内联 CSS |
| 样式方案 | 单个全局内联 `<style>`，126 个手写类，BEM-lite |
| 构建 | 无。Python f-string 插值直接写文件 |
| 静态资源 | 零本地资源；封面全部走 `opengraph.githubassets.com` |
| CDN | 无配置；阿里云只用于 LLM（DashScope），不是资源 CDN |
| 图标 | 10 个手写内联 SVG + 1 个 Unicode `✦` + 2 个纯文本；无命名体系 |
| 响应式 | `--phone: 470px` 固定容器 + **唯一断点 520px** |
| 暗色模式 | **不存在**（全库 0 处 `prefers-color-scheme`） |
| 前端套数 | **4 套 CSS 体系**（生产 3 套 + 死代码 1 套）+ 相邻 skill-picker 的第 5 套暗色 |
| 产物大小 | `feed.html` / `feed.lite.html` 各 **2012 KB**（payload 内联，两者字节数相同） |

## 附录 B：本次读到的关键文件清单

| 文件 | 行数 | 与设计系统的关系 |
|---|---|---|
| `feed_dashboard.py` | 2622 | **唯一生产前端**：CSS 603 行 + HTML 94 行 + JS 1866 行 |
| `feed_pack.py` | 194 | payload 契约 `KEEP_KEYS`；`cover_url_for` |
| `skillfeed.py` | 978 | `build` / `publish-site` 写盘入口（`:606`、`:669`） |
| `server/templates/home.html` | 47 | 第 2 套体系 |
| `server/templates/publish.html` | 129 | 第 3 套体系 |
| `docs/ui-skeleton.html` | 295 | 第 4 套体系（**死代码**） |
| `tests/test_feed_dashboard.py` | 344 | 字面量断言 + node harness，**重构的主要阻力** |
| `.github/workflows/pages.yml` | 114 | CI 只有 Python，无 Node |
| `config_defaults.json` | 50 | 无任何样式/CDN 配置 |
| `docs/PRD.md` | 363 | 交互真相源，**无视觉规格** |
| `AGENTS.md` | 63 | PRD 强同步纪律（未覆盖视觉层） |
| `../skill-picker/dashboard.py` | ~1000 | 第 5 套体系（暗色），iframe 宿主 |
| `../skill-picker/discover.py` | 200 | lite 页 copy / 跨仓 `import feed_dashboard` |
