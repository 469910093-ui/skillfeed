# skill-feed / skillfeeder 前端设计品味评审（只读）

> 判据：`design-taste-frontend` SKILL.md（anti-slop 前端设计品味）
> 评审性质：**只读**。未修改任何产品代码，未提交 git。本文件是本次评审唯一写入的文件。

## 读取时间点与代码状态

所有行号基于 **2026-09-03 16:44 - 17:00 (UTC+8)** 读取的快照：

| 对象 | 状态 |
| --- | --- |
| `feed_dashboard.py` | mtime `2026-09-03 16:43:45`，108,201 bytes |
| `~/.skill-feed/feed.json` | mtime `2026-09-03 16:44:00`，388 items |
| `~/.skill-feed/feed.html` | mtime `2026-09-03 16:44:00`，2,060,444 bytes |
| 运行实例 | `http://127.0.0.1:8473/`（评审期间另有一个 `:8474` 实例，非本次评审对象） |

三个 agent 正在并行改 `feed_dashboard.py` / `i18n.py` / `rank.py`。评审中途 `:8473` 的 feed 内容确实变过一次（卡片列表从 stop-slop / copywriting-skills / internal-comms… 变成 stop-slop / internal-comms / ad-copy…），说明 `feed.json` 被重建过。**行号可能已漂移，请以本文引用的代码片段内容为准而非行号本身。**

已知在修、本文不重复报的问题：卡内重复内容、排序规则缺失、译文缓存重烧 token。凡本文提到与之相关的点，都是**不同的观察角度**，会明确标注「补充视角」。

---

## 1. Design Read（Section 0.B 格式）

> **Reading this as:** 面向中国开发者与内容创作者的 **skill 发现型消费产品（vertical discovery feed）**，用户目标是「在几十秒内判断这个 skill 值不值得装」，语言应当是 **信息密度优先的实用主义（utilitarian, scan-first）**，倾向 **GitHub Primer 式的克制工具感 + 移动端原生信息流的节奏**；当前实现实际落在 **Instagram Web 的像素级仿写皮肤** 上。

这句话的后半段是本次评审最重要的判断，展开说明。

### 界面当前实际是什么：一套 Instagram 设计令牌

`feed_dashboard.py` 的 `:root`（L42-L54）不是「受 Instagram 启发」，而是 Instagram Web 的设计令牌原样搬运：

```42:54:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
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

逐项对照：`#fafafa` 是 IG 背景、`#262626` 是 IG 正文、`#8e8e8e` 是 IG 次级文本、`#dbdbdb` 是 IG 分隔线、`#ed4956` 是 IG 点赞红、`#00376b` 是 IG 链接蓝、`--ring` 是 IG Story 圆环渐变的五个色标、`470px` 是 IG Web 单列宽度。`--logo` 里的 **Billabong 就是 Instagram logo 的字体本身**，`Cookie` 是它的免费仿写；L40 通过 Google Fonts 把两个都加载了：

```40:40:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
<link href="https://fonts.googleapis.com/css2?family=Billabong&family=Cookie&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
```

再加上 `.logo` 把 `--ring` 当作 `background-clip: text` 渲染 wordmark（L79-L87），得到的就是「Instagram 花体 logo + 彩虹渐变字」。

**这不是一个品味瑕疵，是一个定位问题。** 产品的宣发渠道是小红书 / 抖音 / 公众号，目标是被记住成一个独立品牌（skillfeeder.cn）。当前 UI 让用户第一眼看到的是「有人做了个 Instagram 换皮」，而不是「这是 skillfeeder」。Section 0.D 的 Anti-Default Discipline 说的就是这件事：不要落进现成模板，哪怕这个模板不是 AI 默认的紫色渐变，而是另一个大厂的设计系统。

同时，卡片内容区又用了**第二套设计系统 GitHub Primer** 的色值（`#f6f8fa` / `#eaeef2` / `#24292f` / `#0d1117`，见 L262、L310-L311）。Section 2.A 的「One system per project」和 Section 4.2 的「One palette per project」同时被破坏：外壳是 Instagram，内容是 GitHub，两者的灰阶冷暖并不同源。

---

## 2. 三个 dial 的读数

| Dial | 当前实测 | 我认为应该 | 理由 |
| --- | --- | --- | --- |
| `DESIGN_VARIANCE` | **1** | **3 - 4** | 六张卡高度 672/672/672/672/693/693，结构完全同构，封面全部是同一个 `opengraph.githubassets.com` 模板。这是 Section 7 定义的「1-3 Predictable / 对称等距」的极端。信息流本来就该低 variance（可预测性是 feed 的功能），但 **1 太低了**：完全没有「这张不一样」的信号，用户失去停下来的理由。3-4 的意思不是搞不对称排版，而是让**卡片类型分化**（高星大卡 / 普通条目 / 中文原生内容 / 无封面紧凑卡），高度和封面策略随之不同。 |
| `MOTION_INTENSITY` | **2**（且无 `prefers-reduced-motion` 兜底） | **3**（保持低，但补齐 reduced-motion 与 scroll-snap） | 全站只有 5 个 `@keyframes`：`hintFlash` / `postIn` / `burst` / `pulse` / `svFill`，且 `.demo-bar .dot` 是 `pulse 1s infinite`。低 motion 对这个产品是**正确选择**，不用往上加。问题在两头：一是 Section 6.B 要求 `MOTION_INTENSITY > 3` 必须做 reduced-motion，当前虽然只有 2，但存在**无限循环动画**，按规则精神仍应加保护；二是竖向 feed 缺 `scroll-snap`（见 P0-3），这不是「动效」而是「导航语法」的缺失。 |
| `VISUAL_DENSITY` | **7 - 8**（头部 chrome 区达到 9） | **5 - 6** | 470px 宽的列里塞进了：头像行 + 封面图 + 覆盖式徽章 + 「解决」标题 + 3 个带边框的亮点卡 + 「适合」行 + SKILL.md 链接 + 图标操作条 + 星数与 score 行 + 「因为」归因行 + 「为你推荐」标签 + 全宽 CTA，共 **12 个信息层**。Section 4.4 说「cards ONLY when elevation communicates real hierarchy」，这里三个亮点各自套了一个 `#f6f8fa` 边框盒（L308-L312），是容器套容器。降到 5-6 的做法是砍层不是缩字号。 |

---

## 3. 规则适用性判断（本次评审的核心结论之一）

skill 自己在开头和 Section 13 声明：适用于 landing page / portfolio / redesign，**不适用于 dashboard、密集产品 UI、多步产品 UI**。本产品主界面是竖向信息流，属于产品 UI。技术栈也完全不同：没有 React / Next / Tailwind / Motion，整页由 `feed_dashboard.py` 的 Python f-string 拼出自包含单文件 HTML（f-string 内 JS 花括号双写 `{{` `}}`），内联 CSS + 原生 JS。

所以下面把条款分三类。

### 3.1 完全适用（判据有效，且本产品确实违反）

这些条款约束的是**视觉与内容的诚实度**，与页面类型和技术栈无关。

| 条款 | 为什么适用于竖向信息流 |
| --- | --- |
| **9.G em-dash 全面禁用** | 纯文案规则。信息流的卡片文案是产品的主体内容，比 landing page 更需要克制。 |
| **9.F 中点 `·` 限量、装饰性色点、版本号/构建信息外泄** | feed 卡片的元信息条正是这些 tell 的高发区。 |
| **9.A 禁霓虹/过饱和/纯黑、4.2 THE LILA RULE、Color Consistency Lock** | 配色一致性在信息流里**比 landing page 更重要**：landing 只滚一屏两屏，feed 要滚几百张卡，任何随机色都会被放大成噪音。 |
| **9.D 假数据 / 假精确数字** | 星数、score 是这个产品的信任基础。 |
| **4.9 COPY SELF-AUDIT** | 卡片文案 90% 由 LLM 生成，正是这条针对的场景。 |
| **4.5 BUTTON CONTRAST CHECK / NO DUPLICATE CTA INTENT** | CTA 规则与页面类型无关。「打开 GitHub」是产品唯一 CTA，重复入口的代价比 landing page 更高。 |
| **4.11 Page Theme Lock、6.C Dark Mode** | 消费级产品强制要求，信息流是长时间停留场景，暗色模式的需求**强于** landing page。 |
| **6.B Reduced Motion、6.D Core Web Vitals、6.E DOM Cost** | 性能与 a11y 规则通用；无限滚动列表对 DOM 成本更敏感。 |
| **4.1 排版纪律（字号层级、行高、字体选择）** | 通用。 |
| **4.4 SHAPE CONSISTENCY LOCK** | 通用。 |
| **4.8 图片策略（真实图优先、禁 div 假截图、禁图上叠标签）** | feed 的封面策略就是图片策略，**这是本产品最核心的视觉决策**。 |
| **3.E 视口稳定性 `100dvh` 而非 `100vh`** | 移动端为主的产品，比 landing page 更该守。 |

### 3.2 需要「翻译」后适用（原文针对 landing，精神可迁移）

| 原条款 | 在竖向信息流里的等价形式 |
| --- | --- |
| **4.7 Hero 必须在首屏内 / CTA 无需滚动可见** | landing 的「hero」在这里等价于**单张卡片**。卡片是这个产品的最小消费单元，它才是那个「必须在一屏内看完、CTA 必须可见」的东西。按这个翻译，当前是硬性失败（见 P0-1）。 |
| **4.7 Hero stack discipline（最多 4 个文本元素）** | 等价于「单卡最多 N 个信息层」。当前 12 层，远超。 |
| **4.9 内容密度：小标题 ≤ 8 词、副段 ≤ 25 词** | 等价于卡片文案长度预算。当前 `highlights_en` 有 246 条超过 60 字符，英文模式下 18/18 条亮点全部折行成两行。 |
| **9.C 禁三栏等宽卡片** | 等价于「禁止三个等高等宽的亮点盒竖着堆」。当前正是这个图形，只是旋转了 90 度。 |
| **4.7 Bento 要有节奏 / Section-Layout-Repetition Ban** | 等价于**卡片类型要有节奏**。一个 feed 全是同构卡，等于一个 landing page 八个 section 全用同一种布局。 |
| **9.F 禁 eyebrow 式小型全大写标签** | `.time` 的 `text-transform: uppercase; letter-spacing: .04em; font-size: .68rem`（L431-L434）就是 eyebrow 的 CSS 签名，只是它每张卡都出现一次。 |

### 3.3 不适用（本次不作为判据）

| 条款 | 不适用原因 |
| --- | --- |
| **4.7 Hero 视口纪律的字面版**（headline ≤ 2 行、subtext ≤ 20 词、`pt-24` 上边距上限） | 没有 hero 区。整个产品没有营销首屏，打开即内容。上述数字是为「一个页面只有一个首屏」设计的，逐条套没有意义（已在 3.2 翻译为卡片预算）。 |
| **EYEBROW 配额 = ceil(sectionCount / 3)** | 这个配额的分母是「页面 section 数」。信息流没有 section，只有无限重复的 item。机械套用会得出「388 张卡可以有 129 个 eyebrow」这种荒谬结论。**应改判为：重复元素只要在每张卡上出现，就按「1 个」评估其存在价值**，而不是按配额。 |
| **Bento 网格节奏 / BENTO CELL COUNT RULE** | 没有 bento 网格。单列流。 |
| **logo 墙规则（Simple Icons、logo-only、位置在 hero 下方）** | 没有社会证明 logo 墙。 |
| **4.3 ANTI-CENTER BIAS / Split Screen / 非对称留白** | 这些是 landing 的构图多样性要求。单列 feed 的**可预测性本身是功能**，强行非对称会破坏扫读。 |
| **ZIGZAG ALTERNATION CAP（连续 image+text 分栏不超过 2 段）** | 同上，feed 的重复是设计意图，不是懒惰。真正的问题不是「重复」而是「重复且无分化」（已在 3.2 翻译）。 |
| **SPLIT-HEADER BAN / 章节标题右上角浮动小字** | 没有章节标题。 |
| **4.10 引言与推荐语规则（≤ 3 行、署名格式）** | 没有 testimonial 模块。 |
| **Section 3.A 技术栈（React / Next / RSC / `'use client'` / `next/font`）** | 无框架、无构建。RSC、Motion、`useMotionValue`、`useReducedMotion` 全部不适用。**但 `next/font` 背后的意图适用**：L40 用 `<link>` 直连 Google Fonts，在中国大陆是可用性问题而非风格问题（见 P1-6）。 |
| **Section 3.C 图标库（Phosphor / HugeIcons / Radix / Tabler，禁手写 SVG path）** | 没有 npm，装不了图标库。**但「一个项目一个图标家族、统一 strokeWidth」的精神适用**，实测已基本做到（统一 `stroke-width="1.8"`，路径取自 Feather 系）。仅 `.heart-burst` 用 fill 型心形与其余 stroke 型混用，属轻微不一致。**不作为问题上报。** |
| **Section 5.A / 5.B GSAP sticky-stack / horizontal-pan 骨架** | 无 GSAP，无滚动劫持，也不该有。 |
| **Section 2.A 设计系统选型表 / Appendix A 安装命令** | 无构建步骤，装不了。 |
| **Section 11 REDESIGN PROTOCOL** | 本次是评审不是重构。 |

---

## 4. 发现清单

严重度定义：**P0** = 直接损害核心任务或触及可访问性底线；**P1** = 明显削弱产品说服力/可用性；**P2** = 打磨项。

### P0-1 单张卡片放不进一屏，唯一 CTA 永远在折叠线以下

**证据**（Chrome DevTools，模拟 390×844 iPhone 视口，英文模式，页面滚动位置 = 顶部）：

```
topbar        66 px
search-wrap   45 px
stories-wrap 154 px
filter-strip  95 px（两条）
bottom nav    62 px
------------------------
固定 chrome  421 px = 视口高度的 50%

第一张卡 top      y = 359 px
第一张卡 height       633 px
「Open on GitHub」 y = 939 px   ← 比 844 px 视口低 95 px
```

**为什么是问题**：这个产品存在的理由是「让用户点开 GitHub」。在最理想的情况下（第一张卡、页面顶部、最大号主流手机），那个按钮也看不见。按 3.2 的翻译，卡片就是 hero，Section 4.7「CTAs visible without scroll」是硬性失败。更糟的是 chrome 占掉 50% 视口，其中 `.stories-wrap` 独占 154px，而用户未关注任何人时它只显示两个「+」占位圆圈 —— **18% 的首屏面积给了一个空状态**。

**建议方向**：把「一屏 = 一张完整卡片」当作硬性布局约束反推预算。优先压缩 chrome（搜索框与筛选条可在下滑时收起、Stories 在无关注时折叠为一行文字入口），而不是缩小卡片字号。CTA 的位置需要重新决定：要么固定在卡片底部可见区，要么让整张卡可点。

---

### P0-2 竖向信息流没有 scroll-snap，滚动没有落点

**证据**：全站 CSS 中 `scroll-snap` 出现 **0 次**（在页面内枚举全部 CSSOM 规则统计）。`.feed` 与 `html` 的 `scroll-snap-type` 计算值均为 `none`。卡片高度 672 / 672 / 672 / 672 / 693 / 693 px。

**为什么是问题**：产品形态被描述为「类似抖音的竖向信息流」，但实现是 Instagram 式连续滚动。卡片高度 672px 与任何常见视口都不成整数比，结果是**每次停下来都卡在两张卡之间**：上一张的 CTA 和下一张的头像同时出现在屏幕上。这直接放大了 P0-1 —— 用户既看不完整张卡，也不知道自己在第几张。这是「导航语法缺失」，不是动效偏好。

**建议方向**：先确定产品到底是「连续 feed（Instagram 语法）」还是「一屏一卡（抖音语法）」。两种都成立，但必须选一个。若选后者，卡片高度需要由视口驱动（配合 P1-1 的 `dvh`），并补 `scroll-snap-type: y mandatory` + `scroll-snap-align`。若选前者，则 P0-1 的 CTA 可见性要用别的手段解决。

---

### P0-3 全站零 `prefers-reduced-motion`，且存在无限循环动画

**证据**：CSS 中 `prefers-reduced-motion` 出现 **0 次**。同时存在 5 个 `@keyframes`，其中：

```
.demo-bar .dot { animation: pulse 1s ease infinite; }   ← 无限循环，无兜底
.post          { animation: postIn .45s ease both; }     ← 每张卡入场位移 16px
.sv-bar.active i { animation: svFill 3.5s linear forwards; }
```

`.post` 的 `postIn` 会在**每次 feed 重渲染时对所有卡片重放**（切换语言、切换筛选、无限滚动追加都会触发）。

**为什么是问题**：Section 6.B 写明 reduced-motion 是 non-negotiable，且「Infinite loops MUST collapse to static」。前庭功能敏感用户在一个需要长时间滚动的信息流里，会持续暴露在入场位移动画中。

**建议方向**：加一个 `@media (prefers-reduced-motion: reduce)` 块统一关掉 `postIn` / `pulse` / `burst` 的位移与循环，保留透明度变化即可。这是纯增量，无回归风险。

---

### P0-4 次级文本全站对比度不达标（29 处 WCAG AA 失败）

**证据**：在页面内对所有可见文本节点跑 WCAG 对比度计算，**29 处低于 AA**。主因是单一令牌：

| 元素 | 前景 | 背景 | 实测 | 需要 |
| --- | --- | --- | --- | --- |
| `.sub`（`@hardikpandya · HelloGitHub · ★ 16,729`）11.5px | `#8e8e8e` | `#ffffff` | **3.28** | 4.5 |
| `.who-for`（`适合 编辑、作者、内容审核员`）12.2px | `#8e8e8e` | `#ffffff` | **3.28** | 4.5 |
| `.why-line`（`因为 · 内容创作 · …`）12.5px | `#8e8e8e` | `#ffffff` | **3.28** | 4.5 |
| `.time`（`为你推荐`）10.9px | `#8e8e8e` | `#ffffff` | **3.28** | 4.5 |
| `.status`（`更新 9月3日 16:39`）9.9px | `#8e8e8e` | `#fafafa` | **3.14** | 4.5 |
| `.sentinel`（`下滑加载更多 · 已显 6 / 435`）12.8px | `#8e8e8e` | `#fafafa` | **3.14** | 4.5 |
| 头像字母 `HA` 12px/700 | `#ffffff` | `#ffd200` | **1.45** | 4.5 |
| 头像字母 `HE` 12px/700 | `#ffffff` | `#38ef7d` | **1.52** | 4.5 |
| `.nav.on` 激活态 `发现` 9.3px | `#ed4956` | `#ffffff` | **3.69** | 4.5 |

**为什么是问题**：`--muted: #8e8e8e` 是从 Instagram 抄来的，但 Instagram 用它的位置和字号与这里不同。这里它承载的是**「适合谁」「为什么推荐你」这类决策信息**，恰恰是用户判断「装不装」最需要读清楚的内容，却是全页最难读的。头像字母的 1.45:1 基本等于不可读。

**建议方向**：`--muted` 需要一个自己的值而不是沿用 IG 的（白底达到 4.5:1 大约需要暗到 `#767676` 一线）。头像字母不要用白色，改为按底色亮度自动取深/浅前景，或者干脆不要随机底色（见 P1-2）。

---

### P0-5 桌面端完全没有布局，2227px 视口里 79% 是死区

**证据**：`.shell { max-width: var(--phone) }`，`--phone: 470px`（L53、L59-L67）。全站只有一条媒体查询：

```641:644:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
  @media (max-width: 520px) {{
    .shell {{ border: 0; }}
    .story-viewer {{ max-width: 100%; left: 0; transform: none; }}
  }}
```

实测 2227×1253 视口下，`.shell` 宽 470px 居中，左右各 878px 空白（占屏 79%）。截图见 `feed-desktop-top.png`。

**为什么是问题**：`skillfeeder.cn` 是线上多用户站点，从小红书 / 公众号点进来的人有相当比例在桌面浏览器打开。当前桌面体验是「一条 470px 的窄条漂在灰色海洋里」。同时它加剧了 P0-1：桌面上明明有 1253px 高度，卡片却仍然被 470px 的宽度逼成 633px 高，CTA 依然要滚。

**建议方向**：这不需要做响应式重构。最小成本是给 `≥ 1024px` 一个断点，让卡片横向展开（封面在左、文案在右），此时卡片高度会大幅下降，P0-1 在桌面上自然解决。中期可以考虑桌面双列。

---

### P1-1 移动端用 `100vh` 而非 `100dvh`

**证据**：

```57:66:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
  body {{ min-height: 100vh; }}

  .shell {{
    max-width: var(--phone);
    margin: 0 auto;
    min-height: 100vh;
```

CSS 中 `dvh` 出现 0 次，`vh` 出现 4 次。

**为什么是问题**：Section 3.E 明确要求 `min-h-[100dvh]`。iOS Safari 地址栏收起/展开时 `100vh` 不变，导致底部 sticky 导航条被地址栏遮挡或跳动。这个产品底部有 `.bottom` 固定导航（已用了 `env(safe-area-inset-bottom)`，说明作者考虑过刘海但漏了动态视口）。

**建议方向**：`100vh` 换 `100dvh`，保留 `100vh` 作为老浏览器回退。

---

### P1-2 颜色被用来编码「什么都不是」：8 套霓虹渐变按 hash 随机分配

**证据**：

```865:874:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
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

```1000:1002:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
function paletteFor(key) {{
  return PALETTES[hashHue(key) % PALETTES.length];
}}
```

这 8 组是免费渐变素材包（uiGradients 一类）的原样搬运，饱和度普遍逼近 100%。它们被用在：头像底色（L1833）、Stories 圆环内圈（L1833）、关注面板头像（L1175、L1190）、以及 Story 全屏底色（L2082-L2086）。

**为什么是问题**：两层。
1. Section 4.2「Max 1 accent color. Saturation < 80%」+ Section 9.A「NO oversaturated accents / NO neon」直接违反。
2. 更要命的是**语义为零**：颜色由 `hash(repo名) % 8` 决定，与 skill 的行业、质量、来源、新鲜度全都无关。在一个「帮我快速分辨」的产品里，**最响亮的视觉变量承载了 0 bit 信息**，纯粹是噪音。反过来，真正需要区分的维度（行业分类）现在只用一个灰色小药丸表示。

**建议方向**：把颜色这个通道让给 `scene`（行业分类）。九个行业各一个低饱和标识色，全站锁死，头像/圆环/徽章共用。随机渐变直接删掉。

---

### P1-3 Story 全屏底色是标准 AI 紫渐变

**证据**：

```552:562:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
  .sv-slide {{
    position: absolute; inset: 0;
    background: linear-gradient(160deg, #7c3aed 0%, #db2777 45%, #f59e0b 100%);
    transition: background .35s ease;
  }}
  .sv-slide::after {{
    content: ""; position: absolute; inset: 0; pointer-events: none;
    background:
      radial-gradient(circle at 12% 18%, rgba(255,255,255,.28), transparent 42%),
      radial-gradient(circle at 88% 12%, rgba(255,255,255,.18), transparent 36%),
```

**为什么是问题**：`#7c3aed`（violet-600）到 `#db2777`（pink-600）到 `#f59e0b`（amber-500）是 Section 0.D 点名的「AI-purple gradients」，叠加上两个白色 radial 光斑就是 Section 0.D 的「centered hero over dark mesh」。Section 4.2 的 THE LILA RULE 对此有明确的默认禁令。在一个主打「帮你去 AI 味」的产品里出现最标准的 AI 视觉签名，反差过大。

**建议方向**：与 P1-2 合并处理。Story 底色改用该 skill 所属行业的标识色 + 中性深色，去掉多色渐变与光斑。

---

### P1-4 圆角尺度混乱，没有可陈述的规则

**证据**：页面内统计所有元素的计算 `border-radius`：

```
999px → 43 处   50% → 26 处   10px → 27 处
8px   →  6 处   6px  →  6 处   14px →  1 处   12px / 2px / 16px 16px 0 0
```

**为什么是问题**：Section 4.4 SHAPE CONSISTENCY LOCK 允许混合尺度，但要求「有一条写得出来的规则并处处遵守」。当前 999px（药丸）和 50%（圆）和 10px（卡）三套是主力、有迹可循，但 `6px`（`.problem em` 的「解决」标签）、`8px`、`12px`、`14px`、`2px` 是零散例外，说明是逐处随手写的。

**建议方向**：定 3 档（交互元素 = 全圆角、容器 = 10px、头像 = 圆），把 6/8/12/14/2 全部归并。

---

### P1-5 徽章叠在封面图上

**证据**：

```269:277:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
  .media .badges {{
    position: absolute; left: 10px; top: 10px; z-index: 2;
    display: flex; flex-wrap: wrap; gap: 6px;
  }}
  .media .badge {{
    font-size: .66rem; font-weight: 700; color: #fff;
    background: rgba(0,0,0,.45); border: 1px solid rgba(255,255,255,.22);
    backdrop-filter: blur(6px); border-radius: 999px; padding: 3px 8px;
  }}
```

渲染结果：`内容创作` `写作润色` 两个半透明药丸压在 GitHub OG 图左上角。

**为什么是问题**：Section 9.F 明确列为禁止项 —— 「NO pills/labels/tags overlaid on images」。这里还有一个具体后果：GitHub OG 图左上角正好是 **owner/repo 大字标题**的位置，徽章直接压在上面。

**建议方向**：徽章移到图片下方与「解决」行同一栏。这也顺带减少一个信息层。

---

### P1-6 通过 `<link>` 直连 Google Fonts

**证据**：L38-L40 使用 `fonts.googleapis.com` / `fonts.gstatic.com` 的 preconnect + stylesheet。

**为什么是问题**：Section 3.A 说「Never link Google Fonts via `<link>` in production」，原文理由是性能。**在这个产品上理由更硬：目标用户在中国大陆，Google Fonts 域名不可达。** 结果是：Outfit（正文）、Cookie / Billabong（logo）全部加载失败，回退到 `PingFang SC` / `Microsoft YaHei` 和系统 `cursive`。也就是说，**这套精心挑选的字体在主要目标市场根本不生效**，而且每次加载还要等 DNS 超时。本机单文件 HTML 版（双击打开、可能离线）问题相同。

**建议方向**：logo 花体是品牌资产，应当自托管或直接内联为 SVG（顺带解决 P2-3 的渐变字问题）。正文 Outfit 要么自托管子集，要么接受系统字体栈并按系统字体重新校准字号行高。

---

### P1-7 内部排序分数 `score 1.54` 直接展示给终端用户

**证据**：

```419:419:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
  .likes {{ padding: 0 14px; font-size: .86rem; font-weight: 700; }}
```

渲染内容：`★ 16,729 · score 1.54`，`font-weight: 700`。生成处 L1619-L1620：

```
const score = it.personal_score != null ? Number(it.personal_score).toFixed(2)
  : (it.rel_score != null ? Number(it.rel_score).toFixed(2) : '—');
```

**为什么是问题**：`score 1.54` 对一个从小红书点进来的用户没有任何意义 —— 它没有量纲、没有上下限、没有解释。Section 9.F 禁止在消费页面出现 `v1.4.2` / `Build 0048` 这类「CLI/devtool fixture」，内部排序分属于同一类。而且它被加粗放在星数旁边，视觉权重等同于真实社会证明，实际是噪音。同时它命中 Section 4.9 的「fake-precise numbers」：两位小数暗示了一种并不存在的精度。

**建议方向**：默认隐藏，放到 debug 开关后面。如果确实想传达「为什么排这么前」，用户能理解的是「本周新增」「同类里星数最高」这种自然语言，而 `.why-line` 已经在做这件事了。

---

### P1-8 同一个 repo 被拆成最多 20 张卡，封面/星数/头像完全相同

**证据**（`feed.json`，388 items）：

```
不同 full_name 只有 57 个，items 却有 388
sickn33/agentic-awesome-skills   20 张   stars=45,883
mattpocock/skills                20 张   stars=245,604
affaan-m/ECC                     20 张   stars=246,534
vivy-yi/xiaohongshu-skills       20 张   stars=None
larksuite/cli                    20 张   stars=16,955
addyosmani/agent-skills          20 张   stars=91,789
...

相邻两张卡属于同一 repo：38 / 387 次（9%）
最长连续同 repo 段：4 张（larksuite/cli）
前 20 张卡里，不同封面图只有 12 张
实际顺序片段： …#17 deepvector  #18 vivy-yi  #19 vivy-yi  #20 vivy-yi  #21 anthropics…
```

**为什么是问题**：封面 URL 是 `https://opengraph.githubassets.com/1/{owner}/{repo}`，是 **repo 级**而非 skill 级。星数同理。头像色由 owner hash 决定。所以同一 repo 的 20 张卡在视觉上**完全一致**，只有正文文字不同。第 18/19/20 张连续三张 `vivy-yi/xiaohongshu-skills`，用户看到的是三张一模一样的图，配三段不同的字，全部标着 `★ —`。

这是「feed 为什么看着像模板」的**根因**，比任何配色问题都严重。它同时污染两件事：
1. **alt 文本与图不符**。实测 `alt="internal-comms"` 的图片 `src` 是 `anthropics/skills` 的 OG 图；`alt="copywriting-skills"` 的 src 是 `vivy-yi/xiaohongshu-skills`。屏幕阅读器读到的和视觉呈现的不是一个东西。
2. **社会证明失真**。`anthropics/skills` 的 173,323 星被印在它旗下每一个子 skill 卡上；`affaan-m/ECC` 显示 246,534 星（这个数字本身也存疑）。用户会以为「这个 skill 有 24 万星」。Section 9.D 禁止 fake numbers，这里的数字是真的，但**归属是错的**，效果一样。

**建议方向**：这是排序/去重问题也是视觉问题，与正在进行的排序引擎改造有交集。视觉侧的方向是：同 repo 的多个 skill 需要**折叠成一张卡 + 内部横滑**，或者至少保证同 repo 卡片不相邻且封面要有 skill 级差异化（例如用 skill 名生成排版式封面，而不是复用 repo OG 图）。星数需要明确标注为「所属仓库星数」而不是裸露的 `★ N`。

---

### P1-9 英文模式下 66 处 em-dash 来自 LLM 改写管线

见第 5 节 AI Tells 专项，此处不重复。

---

### P1-10 26 个可点击元素无法用键盘访问

见第 6 节可访问性专项。

---

### P2-1 `.time` 是一个每张卡都出现、内容恒定的 eyebrow

**证据**：

```431:434:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
  .time {{
    padding: 2px 14px 14px; font-size: .68rem; color: var(--muted);
    letter-spacing: .04em; text-transform: uppercase;
  }}
```

渲染内容恒为 `为你推荐`（英文 `FOR YOU`）。

**为什么是问题**：`font-size: .68rem` + `uppercase` + `letter-spacing` 是 Section 9.F 描述的 eyebrow CSS 签名。按 3.3 的判断，eyebrow 配额规则不适用于 feed，但**「这个元素存在的价值」这一问题仍然成立**：整个 feed 里每一张卡都说「为你推荐」，它不区分任何东西。而且 `text-transform: uppercase` 对中文完全无效，只是给中文加了字距。这个类名叫 `.time`，说明它原本是 Instagram 的时间戳位置，被改成了固定标签，功能却没跟上。

**建议方向**：要么删掉（`.why-line` 已经在解释推荐理由），要么恢复它的本职：显示 skill 的更新时间 / 入库时间，那才是 feed 用户真正会看的信号。

---

### P2-2 亮点列表的 `✦` 装饰符

**证据**：

```313:316:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
  .pitch .highlights li::before {{
    content: "✦"; position: absolute; left: 10px; top: 8px;
    color: var(--like); font-size: .75rem;
  }}
```

**为什么是问题**：四角星 `✦` 是当下最具辨识度的「AI 生成内容」视觉签名（几乎所有 AI 产品用它标注 AI 功能）。用红色 `#ed4956` 强调后，每张卡出现三次，全屏 6 到 9 次。Section 9.F 对「装饰性色点」的禁令针对的正是这种「每一行前面都放一个彩色小符号」的模式。在一个主打「去 AI 味」的产品里，这个符号的讽刺意味比较强。

**建议方向**：换成中性的短横线或直接用留白/缩进区分，把红色留给真正的交互态（点赞）。

---

### P2-3 wordmark 用渐变文字

**证据**：L79-L87，`.logo` 用 `--ring`（IG Story 五色渐变）做 `background-clip: text`。

**为什么是问题**：Section 9.A「NO excessive gradient text for large headers」。叠加 P1-6（Billabong/Cookie 在大陆加载失败），实际效果是「系统 cursive 字体 + 五色渐变」，比纯色更难看。

**建议方向**：wordmark 改为单色或内联 SVG，与 P1-6 一并处理。

---

### P2-4 首屏封面图 `loading="lazy"`

**证据**：`<img class="cover" src="https://opengraph.githubassets.com/1/…" loading="lazy" …>`，六张封面全部 `loading="lazy"`，包含第一张。图片自然尺寸 1200×600，显示宽度 469px，未设 `width`/`height` 属性。

**为什么是问题**：Section 6.D 要求 LCP < 2.5s 且首图应 preload。第一张封面就是 LCP 元素，给它 `lazy` 是反向优化。

**建议方向**：第一张 `loading="eager"` + `fetchpriority="high"`，其余保持 lazy。`.media` 已用 `aspect-ratio` 预留了空间，CLS 风险不大，但补上 `width`/`height` 更稳。

---

### P2-5 筛选条横向溢出 2.5 倍且无边缘提示

**证据**（390px 视口）：行业筛选条 `scrollWidth = 956px / clientWidth = 390px`；栏目筛选条 `scrollWidth = 1054px / clientWidth = 390px`。`.stories` 与筛选条都设了 `scrollbar-width: none` 且隐藏了 webkit 滚动条（L159-L162）。截图 `feed-mobile-en.png` 里可见 `Data & Re` 被硬切在右边缘。

**为什么是问题**：滚动条被隐藏、没有渐隐遮罩、没有箭头，唯一的可滚动提示是「文字被切了一半」。桌面端（无触摸）尤其难发现还有 10 个行业在右边。

**建议方向**：加右侧渐隐遮罩，桌面端补左右箭头。

---

### P2-6 中文用词不一致：`其他` 与 `其它`

**证据**：行业筛选最后一项是 `其他`，栏目筛选最后一项是 `其它`。英文模式下两者都翻成 `Other`，界面上出现两个同名按钮。

**建议方向**：统一为 `其他`；英文侧给两个维度不同的措辞（例如 `Other industries` / `Other topics`）以消歧。

---

### P2-7 单条数据里残留人工标注 `【人工改过】`

**证据**：全量 388 条中有 1 条 `one_liner_zh` 以方括号标记开头：`【人工改过】一键洗掉 AI 腔，让文字像人写的`。渲染后是 `解决 【人工改过】一键洗掉…`。

**为什么是问题**：`【人工改过】` 是内部编辑标记，对用户无意义。数量只有 1 条，故列 P2，但值得在数据管线里加一条正则拦截。

---

## 5. AI Tells 专项（对照 Section 9 逐项）

| Section 9 条目 | 命中 | 证据 |
| --- | --- | --- |
| **9.G em-dash 全面禁用** | **命中，且是全文最严重的一条** | 见下方展开 |
| 9.A 霓虹 / 外发光 | **命中** | `PALETTES` 8 组近满饱和渐变（L865-L874），`.sv-slide` 紫粉琥珀渐变（L554） |
| 9.A 纯黑 `#000000` | 未命中 | 最深为 `#0d1117` / `#262626` |
| 9.A 过饱和强调色 | **命中** | 同上，`#7028e4` `#00f2fe` `#38ef7d` `#fc466b` 等 |
| 9.A 大标题渐变文字 | **命中（轻）** | `.logo` 渐变 wordmark（L79-L87） |
| 9.A 自定义鼠标指针 | 未命中 | 无 |
| 9.B Inter 作默认字体 | 未命中 | 用了 Outfit，符合建议 |
| 9.B 超大 H1 | 未命中 | 最大正文 `.problem` 仅 .95rem |
| 9.C 数学上过于完美的间距 | 不适用（feed 需要一致间距） | |
| 9.C 三栏等宽卡片 | **命中（变体）** | 三个等宽亮点盒竖排（L305-L312），是同一图形旋转 90 度 |
| 9.D 通用假名字 | 未命中 | 全是真实 GitHub owner |
| 9.D 通用头像 | **命中（轻）** | 2 字母首字母 + hash 随机底色，且对比度 1.45:1 |
| 9.D 假数字 | **命中（归属错误型）** | 173,323 / 246,534 星印在子 skill 卡上（P1-8）；`score 1.54` 的两位小数假精度（P1-7） |
| 9.D 创业味假品牌名 | 未命中 | |
| 9.D 填充动词（Elevate / Seamless / Unleash） | 未命中 | 抽查中文文案未见 |
| 9.E 手写 SVG 图标 | 不作为问题 | 无构建步骤，路径取自 Feather 系，`stroke-width` 统一 1.8。见 3.3 |
| 9.E div 假截图 | **未命中（做得对）** | 封面是真实 `opengraph.githubassets.com` 图片，不是 div 拼的假 GitHub 卡 |
| 9.E 失效的图片链接 | 未命中 | 有 `onerror` 兜底到 `.no-cover` |
| **9.F 图上叠标签** | **命中** | `.media .badges`（L269-L277），见 P1-5 |
| **9.F 中点 `·` 限量（每行最多 1 个）** | **命中** | 当前可见文本共 37 个 `·`。`.why-line` 每行 **3 个**（`因为 · 内容创作 · 写作润色 · HelloGitHub`），`.sub` 每行 **2 个**（`@hardikpandya · HelloGitHub · ★ 16,729`），`.likes` 1 个 |
| **9.F 版本号 / 构建信息外泄** | **命中（等价物）** | `score 1.54`（P1-7）；调试用漏斗信息 `漏斗：trending — · search — ·`（L1896） |
| **9.F eyebrow 式小型全大写标签** | **命中** | `.time`（L431-L434），见 P2-1 |
| 9.F 章节编号 eyebrow | 未命中 | |
| **9.F 装饰性色点** | **命中（等价物）** | `✦` 红色装饰符每卡三次（L313-L316），见 P2-2；`.demo-bar .dot` 红色脉冲圆点 |
| 9.F 地点 / 天气 / 时间条 | 未命中 | |
| 9.F 滚动提示（Scroll cue） | **边界命中** | `.sentinel` 文案 `下滑加载更多 · 已显 6 / 435`。Section 9.F 禁「Scroll to explore」类装饰，但这里带真实进度（6/435），属于**有信息量的加载指示**，判定为合规。不过 `已显` 是 `已显示` 的截断，属文案 bug |
| 9.F 微型元叙述句 | 未命中 | |
| 9.F hero 底部装饰文字条 | 不适用 | 无 hero |
| 9.F 长列表每行 `border-t` + `border-b` | 未命中 | 卡间只有 `border-bottom` |
| 9.F 带底轨的进度/评分条 | 未命中 | |

### em-dash 专项展开

Section 9.G 是零容忍条款。当前有**两个独立来源**。

**来源一：源码里 9 处硬编码**（`feed_dashboard.py`，均为用户可见）

| 行 | 内容 |
| --- | --- |
| L652 | `<div class="status" id="genStatus">更新 —</div>` |
| L804 | `notUsefulToast: 'Noted — fewer like this from now on'` |
| L1013 | `if (!g) return lead + '—' + host;` |
| L1618 | `const stars = (it.stars == null) ? '—' : …`（卡片星数缺省值） |
| L1620 | `… : (it.rel_score != null ? … : '—');`（score 缺省值） |
| L1733 | 发布者面板星数缺省值 |
| L1886 | `关键词：<b>${{intent}}</b> — Feed 内暂无匹配，可到 GitHub 继续搜。`（**空状态文案**） |
| L1896 | `漏斗：trending ${{…}} · search ${{…}} ·` 三处 `'—'` |
| L2093 | Story viewer 星数缺省值 |

实测页面上 `★ —` 出现 4 次（`@vivy-yi` 和 `@mythkiven` 两张卡各 2 次，因为它们 `stars=None`）。`feed.json` 里 `stars` 为 `None` 的有 **56 条**，也就是说约 14% 的卡片会渲染出 em-dash。

**来源二：LLM 改写管线产出的英文文案**（`feed.json`，388 items）

| 字段 | em-dash 数 | 示例 |
| --- | --- | --- |
| `highlights_en[]` | **51** | `Reports only actual changes—no noise`、`Pay via non-custodial wallets—no private key sharing` |
| `one_liner_en` | **15** | `Resolve or generate audio, video, images, voice, and other media — output local files…` |
| 合计（英文模式可见） | **66** | |

另外 `highlights_en[]` 里还有 9 个 en-dash `–`，Section 9.G 同样禁止。

**中文侧是干净的**：`highlights_zh` / `one_liner_zh` / `who_for_zh` 三个展示字段实测 **0 个 em-dash、0 处未译英文、0 处 markdown 残留**。em-dash 集中在英文改写结果里。（源字段 `highlights` / `one_liner` / `description` / `body_preview` 合计有 493 个 em-dash，但那些是抓取来的 SKILL.md 原文，不直接渲染。）

**建议方向**：两处都要堵。缺省值 `'—'` 换成 `-` 或干脆不显示星数行；`i18n.py` 的英文 prompt 里加一条硬约束并在入库前做正则替换（`—` `–` → `-`），这个替换应该放在写库前而不是渲染时，否则缓存里会一直留着。

---

## 6. 可访问性专项

### 6.1 对比度

见 P0-4，29 处 AA 失败，根因是 `--muted: #8e8e8e`（3.28:1）和随机头像底色（1.45:1 / 1.52:1）。

**通过的部分**：主 CTA `.open-gh` 是 `#262626` 底 + 白字，对比度约 14:1，很好；`.follow-mini` 深色药丸同理；`.doc-link` 用 `--link: #00376b` 约 12:1，也没问题。

### 6.2 禁用了缩放

```36:36:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
```

`maximum-scale=1` 阻止双指缩放，违反 WCAG 2.1 SC 1.4.4 (Resize Text)。对一个次级文本只有 9.9px 到 12.5px、且对比度本就不足的界面来说，这条尤其伤 —— 用户连「放大看清楚」这个自救手段都被拿掉了。**建议直接删掉 `maximum-scale=1`。**

### 6.3 焦点状态

全站 `:focus-visible` 出现 **0 次**，`:focus` 只有 1 条：

```126:126:D:\Users\yaowenliang\Projects\skill-feed\feed_dashboard.py
  .search:focus {{ outline: 2px solid #c7c7c7; outline-offset: 0; background: #fff; }}
```

好消息是没有任何 `outline: none` / `outline: 0`，所以浏览器默认焦点环仍在工作，键盘用户不至于完全失明。但这意味着焦点样式完全交给浏览器默认值，在 `#fafafa` 浅底 + 深色药丸按钮上，Chrome 默认焦点环的可见性没有被验证过。搜索框自定义的 `#c7c7c7` 焦点环对 `#efefef` 背景只有约 1.3:1，几乎看不见（WCAG 2.1 SC 1.4.11 要求非文本对比 3:1）。

**建议方向**：加一条全局 `:focus-visible` 规则，用 `--ink` 或 `--like` 做 2px outline + 2px offset；搜索框的 `#c7c7c7` 需要加深。

### 6.4 键盘导航

**26 个带点击行为的元素不可聚焦**（`DIV` / `SPAN`，无 `tabindex`、无 `role`）：

| 元素 | 数量 | 功能 |
| --- | --- | --- |
| `div.avatar.clickable.js-publisher` | 6 | 打开发布者面板 |
| `div.who.clickable.js-publisher` | 6 | 同上 |
| `div.media.js-media` | 6 | 双击点赞 |
| `span.badge.clickable.js-scene-tag` | 6 | 关注行业 |
| `div.sv-tap-left` / `div.sv-tap-right` | 2 | Story 上一条 / 下一条 |

其中 `sv-tap-left` / `sv-tap-right` 有 `aria-label`（`上一条` / `下一条`）却是 `div` 且不可聚焦 —— 加了标签但没加可达性，屏幕阅读器用户会被告知有这个控件却无法使用它。**Story viewer 的翻页在键盘上完全不可用。**

另有 **2 个 button 既无文本也无 `aria-label`**，屏幕阅读器只会读「按钮」。

**建议方向**：`.clickable` 的元素换成 `<button>`（这个代码库里 `.story` 和 `.nav` 已经这么做了，是现成的正确范例），或者至少补 `tabindex="0"` + `role="button"` + Enter/Space 键处理。

### 6.5 aria-label 语言混乱

同一时刻页面上的 `aria-label` 有中有英，且**不随语言开关变化**：

```
DIV.lang-toggle    => 语言 / Language
DIV.stories        => 关注动态 Stories
DIV.filter-strip   => 行业筛选 / 二级场景 / 栏目
BUTTON.sv-close    => 关闭
DIV.sv-tap-left    => 上一条
DIV.sv-tap-right   => 下一条
BUTTON.act         => like            ← 英文，中文模式下也是英文
BUTTON.act         => not useful      ← 英文
BUTTON.act         => save            ← 英文
BUTTON.hint-close  => Dismiss         ← 会随语言变
```

也就是说：中文模式下，屏幕阅读器把点赞按钮读成 "like"；英文模式下，把关闭按钮读成「关闭」。两个方向都错。`.sr-only` 的两条文本（`一级场景` / `二级场景`）同样恒为中文。

另外 `div.filter-strip` 带 `aria-label` 但没有 `role`，多数屏幕阅读器会忽略无角色元素上的 label。

### 6.6 reduced-motion

见 P0-3。零支持，且有无限循环动画。

### 6.7 暗色模式

`prefers-color-scheme` 全站出现 **0 次**，没有 `.dark` 类，也没有 `[data-theme]`。产品是**纯浅色单模式**。

Section 6.C 说「mandatory for any consumer-facing page」。对一个「躺着刷」的信息流产品，这条比对 landing page 更硬：用户很可能在夜间使用。同时这也说明 Section 4.11 Page Theme Lock 目前是「合规但因为没有第二个模式」—— 值得注意的是，卡片封面区是 `#0d1117` 深底（GitHub OG 图的深色版本），在 `#ffffff` 卡片里形成一块深色区。这在单模式下可以接受（图片本来就有自己的色彩），但一旦要做暗色模式，需要重新设计封面区与卡片底的关系。

**建议方向**：现有 CSS 已经全部走 `:root` 变量，加暗色模式的成本主要在于**重新选一套暗色令牌**（不能简单反转，`--like: #ed4956` 在深底上会过亮），而不是重构结构。这是目前架构给的一个便宜。

---

## 7. 中英双语专项

结论：**正文层的双语质量很好，a11y 层和少数系统文案完全没进 i18n 管线。**

### 7.1 做得好的部分

- `document.documentElement.lang` 正确随开关切换（`zh-CN` / `en`）。
- 语言选择通过 `localStorage.sf_lang` 持久化，刷新后保持。
- 全部行业标签、栏目标签、按钮文案、卡片正文、亮点、「适合」行、底部导航都有完整英文版本。`feed.json` 里 387/388 条有 `one_liner_en` 和 `highlights_en`。
- 日期格式随语言切换（`更新 9月3日 16:39` / `Updated Sep 3, 04:39 PM`）。
- 无中英串档：`highlights_en` 1154 条里只有 **1 条**残留中文字符；`highlights_zh` 1233 条里 **0 条**是纯英文。

### 7.2 漏译清单（英文模式下仍是中文）

| 位置 | 内容 | 类型 |
| --- | --- | --- |
| `.sentinel` | `下滑加载更多 · 已显 6 / 435` | **可见文本** |
| `.sr-only` × 2 | `一级场景` / `二级场景` | 屏幕阅读器文本 |
| `div.lang-toggle[aria-label]` | `语言 / Language` | aria |
| `div.stories[aria-label]` | `关注动态 Stories` | aria |
| `div.filter-strip[aria-label]` × 3 | `行业筛选` / `二级场景` / `栏目` | aria |
| `button.sv-close[aria-label]` | `关闭` | aria |
| `div.sv-tap-left/right[aria-label]` | `上一条` / `下一条` | aria |

反向（中文模式下仍是英文）：`button.act[aria-label]` 的 `like` / `not useful` / `save`。

`.sentinel` 是唯一一处**肉眼可见**的漏译，优先级最高。其余是 a11y 层，说明 i18n 管线只覆盖了「渲染进 DOM 文本节点的字符串」，没有覆盖属性和 `.sr-only`。

### 7.3 英文模式的排版问题

这是双语专项里比漏译更严重的部分。

**每一条亮点都折行成两行。** 实测 390×844 视口、英文模式，`.highlights li` 共 18 条，**18/18 全部为 2 行**（中文模式下为 1 行）。原因是 `highlights_en` 里有 **246 条超过 60 字符**，而中文亮点普遍在 26 字符以内：

```
(103) Runs multi-round targeted searches across definitions, principles, comparisons, and latest dev…
 (68) Cross-verifies info from diverse sources to avoid single-search bias
 (65) Saves ready-to-use report in conventional location with citations
```

后果：卡片在英文模式下比中文模式高一截，本来就在折叠线以下的 CTA 更远（P0-1 的实测 939px 就是英文模式的数字）。同理 `one_liner_en` 有 15 条含 em-dash 且普遍偏长。

**建议方向**：`i18n.py` 的英文 prompt 需要给出**硬字数上限**（亮点 ≤ 8 词或 ≤ 55 字符），并在入库时校验，超长的重新生成或截断。这与正在进行的「译文入库」改造是同一处代码，可以一并处理。中文侧也有 81 条 `highlights_zh` 超过 26 字，73 条 `one_liner_zh` 超过 34 字，同样值得设上限，但没到必然折行的程度。

### 7.4 英文措辞歧义

行业筛选和栏目筛选的最后一项在中文里是 `其他` 和 `其它`（本身就不一致，见 P2-6），英文都译成 `Other`，导致同屏出现两个完全同名的按钮，无法区分。

---

## 8. 最该先动的三件事（按投入产出排序）

### 第一件：把「一屏 = 一张完整卡片」变成硬约束

对应 **P0-1 + P0-2 + P0-5**，顺带缓解 P1-8。

这是唯一直接作用于产品核心指标（点开 GitHub 的比例）的改动。当前状态是：产品唯一的 CTA 在最理想条件下也要滚 95px 才能看见，而滚动又没有落点，用户永远停在两张卡中间。

具体三步，按顺序：
1. **先算预算再改样式**。定下「移动端一屏必须容纳：封面 + 解决 + 3 条亮点 + CTA」，反推固定 chrome 的上限。当前 chrome 是 421px / 50%，目标砍到 25% 以内。最大的一块是 `.stories-wrap` 的 154px，而它在无关注状态下只装两个「+」占位。
2. **决定滚动语法**。连续 feed 还是一屏一卡，选一个。选后者就补 `scroll-snap`，卡片高度由 `100dvh` 驱动（同时解决 P1-1）。
3. **给桌面端一个断点**。`≥ 1024px` 让卡片横向展开，桌面上 79% 的死区变成可用宽度，卡片高度自然下降，CTA 上浮。

这件事投入最大，但它是唯一一件「不做，其他所有优化都是在装修一个走不通的房子」的事。

### 第二件：一次性清掉可访问性硬伤

对应 **P0-3 + P0-4 + 6.2 + 6.3 + 6.4 + 7.2**。

这些全是**低风险、无需重新设计、可以并行做**的修补，加起来大概是一天的量，但能把产品从「有 29 处 AA 失败 + 禁用缩放 + 26 个键盘不可达控件」拉到基本合格：

- 删掉 `<meta viewport>` 里的 `maximum-scale=1`（一行）。
- `--muted` 从 `#8e8e8e` 调深到 4.5:1（一行，全站生效）。
- 加 `@media (prefers-reduced-motion: reduce)` 块（一个 block）。
- 加全局 `:focus-visible` 规则（一个 block）。
- `.clickable` 的 div/span 换成 `<button>`（代码库里 `.story` / `.nav` 已经是正确写法，照抄即可）。
- `aria-label` 和 `.sr-only` 接入 `tr()`，`.sentinel` 补英文。

单位投入的产出在这三件里最高，而且它和另外两件、以及三个 agent 正在做的改动都不冲突。

### 第三件：拆掉「Instagram 皮肤」，把颜色还给信息

对应 **P1-2 + P1-3 + P1-4 + P1-5 + P2-2 + P2-3 + P1-6**，以及第 1 节的 Design Read。

这件事排第三不是因为不重要，而是因为它需要先有前两件的结构基础，且需要一次真正的设计决策而不是修 bug。核心是三个动作：

1. **换掉 IG 令牌**。`--bg` / `--ink` / `--muted` / `--line` / `--like` / `--link` / `--ring` / `--logo` 这一整组需要重新定义成 skillfeeder 自己的东西。这不是「换个颜色」，是这个产品有没有品牌的问题 —— 现在从小红书点进来的用户看到的是 Instagram，不是 skillfeeder。
2. **颜色只编码行业**。删掉 `PALETTES` 的 8 组随机霓虹渐变和 `paletteFor()` 的 hash 分配，改为 9 个行业各一个低饱和标识色，头像 / 圆环 / 徽章 / Story 底色共用。同时 `.sv-slide` 的紫粉琥珀渐变（AI 视觉签名，出现在一个主打「去 AI 味」的产品里）一并替换。
3. **顺手清掉小 tell**：徽章从图上挪到图下、`✦` 换成中性符号、圆角归并到 3 档、wordmark 改内联 SVG（同时解决 Google Fonts 在大陆加载不到的问题）。

---

## 附：本次评审用到的截图

| 文件 | 内容 |
| --- | --- |
| `feed-desktop-top.png` | 2227×1253 桌面视口，470px 窄条 + 左右各 878px 死区 |
| `feed-mobile-en.png` | 390×844 手机视口，英文模式，可见 chrome 占 50%、CTA 在折叠线外、筛选条被硬切 |

截图保存在 `%TEMP%\cursor\screenshots\`。
