# skill-feed 信息流排序引擎设计

状态：**已评审通过，后端已实现**
适用：线上多用户站点（skillfeeder）为主，本机单用户版复用同一打分核心
撰写依据：用户三条规则 + 已拍定的三条决策 + 评审中发现的缺陷清单

> **实现分轮**：本轮只做后端（打分核心、埋点接口、画像存储、限流、配置、单测）。
> 前端埋点（impression / dwell / open_github / not_interested / focus_set 的采集与上报）
> 单独一轮做，施工依据是 `docs/frontend-event-contract.md`。
> 后端已按契约就绪，前端没上线之前排序自动退化到全局质量分 `G`。

---

## 0. 一句话概括

三条规则不做成三种模式，收敛成**一个打分函数**：

```
score(item, device) = w_g·G(item) + w_p·P(item,device) + w_f·F(item,device) − w_n·N(item,device) + ε(item,session)
```

权重随「画像置信度」连续变化（不是 if/else 切模式），后接**多样性硬约束**重排和**固定探索位**注入，
最外层是一套**仲裁顺序**决定搜索/筛选何时压过个性化。

---

## 1. 北极星指标与埋点口径

### 北极星

**会话级 GitHub 打开率** = `至少产生 1 次 open_github 的会话数 / 总会话数`

为什么不用逐次曝光 CTR：逐次 CTR 可以靠「少展示、只展示安全牌」刷高，与产品目标（帮用户发现能装的 skill）相反。
会话级打开率奖励的是「这一趟逛下来有没有真的找到东西」。

### 护栏指标（不可回退）

| 指标 | 含义 | 目标 |
|---|---|---|
| `distinct_scenes_per_session` p50 | 单会话看到的一级行业数 | ≥ 4，监控茧房 |
| `session_depth` p50 | 单会话浏览卡片数 | 不下降，监控疲劳 |
| `new_item_impression_share` | 新上架条目占总曝光比 | ≥ 8%，验证冷启动真的在跑 |
| `not_interested_rate` | 不感兴趣事件 / 曝光 | ≤ 1.5% |
| `exploration_slot_ctr / overall_ctr` | 探索位相对效率 | 0.5 ~ 1.0（低于 0.5 说明探索池选得烂，高于 1.0 说明主排序太保守） |

### 次级指标

`open_github_per_session`（次数，非会话率）、设备维度 D1/D7 回访率、`focus_set` 设置率。

---

## 2. G(item)：全局质量分（build 期算，全站共享）

输出 [0,1]。五项加权：

| 分项 | 权重 | 计算 | 为什么是这个权重 |
|---|---|---|---|
| `ctr_score` | **0.34** | COEC + Wilson 下界，见 2.1 | 唯一反映「本站用户真实反应」的信号，对应规则 1 后半句，所以领跑 |
| `velocity_score` | **0.28** | star 增速，见 2.2 | star 存量会让 feed 每天一模一样，增速是修法，权重必须压过存量 |
| `stock_score` | **0.14** | `log10(1+stars)` 归一，再按仓库级证据强度收缩，见 2.4 | 保留一个可信度地板，防止「3 曝光 2 点击」的小库靠 CTR 冲顶；但刻意压小 |
| `freshness_score` | **0.12** | 首次入库天数指数衰减，半衰期 14d | 拉动新内容 |
| `completeness_score` | **0.12** | 有 SKILL.md / 有中文一句话 / 有 highlights / 描述长度 | 卡片渲染质量直接影响点击，是质量而非噱头 |

`G = Σ w_k · part_k`，各分项先各自压到 [0,1]。

### 2.1 CTR：位置去偏 + Wilson 下界 + 场景先验

**位置去偏（COEC，Click Over Expected Click）**

曝光按位置分档记录：`band0 = 位置 0–4`、`band1 = 5–14`、`band2 = 15–39`、`band3 = 40+`。

全站先算每档的平均点击率 `ctr_band[b]`，再算条目的期望点击数：

```
expected(i) = Σ_b  impressions(i,b) · ctr_band[b]
observed(i) = Σ_b  clicks(i,b)
```

`observed / expected` 就是「相对位置期望的表现」，天然消掉「排得高所以点得多」的回路。

**低曝光压制（贝叶斯先验 + Wilson 下界）**

不直接用比值。先用该条目所属 `scene_l2` 的全站先验 CTR `prior(i)` 做平滑，再取 Wilson 95% 下界：

```
n_equiv = expected(i) / ctr_overall          # 等效「平均位置曝光次数」
k_equiv = observed(i)                        # 实际点击数
n = n_equiv + α                              # α = 20，先验强度
k = k_equiv + α · prior(i)
ratio_lb = wilson_lower(k, n, z=1.96) / ctr_overall
```

**再往中性混合一次**（这一步不能省）：

```
conf = n_equiv / (n_equiv + α)
ratio = 1.0 · (1 − conf) + ratio_lb · conf
ctr_score = squash(ratio)                    # ratio 1.0 → 0.5，2.0 → 0.67
```

为什么要这层混合：Wilson 在 n 很小时区间极宽，光靠先验平滑，
0 曝光会算出 ratio ≈ 0.24 而不是中性 1.0。那样「从没被展示过」反而成了劣势，
且 0 曝光(1.0 特判) 与 1 曝光(0.24) 之间出现悬崖。按置信度混合把这条曲线抹平。

实测效果（ctr_overall = 8%，α = 20，均已单测锁定）：

| 情况 | 原始 CTR | 本方案 ratio |
|---|---|---|
| 曝光 3 / 点击 2 | 66.7%（= 8.3 倍平均） | ≈ 0.97（**回落到平均，冲不了榜**） |
| 曝光 500 / 点击 60 | 12% | ≈ 1.16（可信的高于平均） |
| 曝光 500 / 点击 10 | 2% | ≈ 0.19（可信的低于平均，压下去） |
| 曝光 0 | — | = 1.0（中性，不奖不罚） |

**这就是「曝光 3 次点 2 次不能冲榜首」的具体解法。**

> ⚠️ **依赖新埋点**：目前 `feedback.py` 只记 useful/opened_github/bad，没有 impression。
> CTR 在埋点上线并积累前，`ctr_score` 恒等于 1.0（中性），G 退化成 velocity + stock + freshness + completeness 四项。
> 这是预期行为，不是 bug。

### 2.2 star 增速：三级数据源降级

现实约束（已核对 `~/.skill-feed/feed.json`，388 条里 **只有 2 条 `stars_today` 非 0**，因为该字段只有 trending 源才有）。
所以增速必须自己攒：

| 优先级 | 数据源 | 说明 |
|---|---|---|
| 1 | `stars_today` | trending 源直给，最准 |
| 2 | 自维护 star 快照 `~/.skill-feed/rank_state/stars_history.jsonl` | 每次 build 落一行 `{full_name, stars, date}`，两次观测即可算日均增速。需要 2~3 天预热 |
| 3 | 用 corpus `ingested_at` 做「首次见到」代理，`stars / age_days` 粗算 | **弱代理**：入库时间不是仓库创建时间，只能当兜底 |

数据源不同，置信度不同：`velocity_score = squash(daily_gain / 30) · confidence`，
confidence 分别为 1.0 / 0.85 / 0.4。没有任何数据时 `velocity_score = 0.25`（中性偏低，不惩罚也不奖励）。

> **已裁决：走 A** —— `star_history.py` 自己按 `SKILLFEED_HOME` / `~/.skill-feed` 解析目录
> （与 `server/config.data_home()` 同一套逻辑），`pack_feed()` 直接调用，不改 `skillfeed.py` 调用点。
>
> B（由调用方注入 `data_dir`）在架构上更正派，但当时 `skillfeed.py` 有并发改动，
> 跨 agent 协调两处调用点的代价高于这点架构收益。取舍原因写在 `star_history.py` 的模块 docstring 里，
> 以后重构的人不会误以为这是设计品味问题。所有对外函数保留 `data_dir` 参数可显式覆盖，单测走显式路径。

### 2.4 star 是仓库级信号：monorepo 继承问题

**实测数据（388 条）**：来自 57 个仓库，**363 条（93.6%）是 monorepo 拆出的子 skill**，
单仓最多拆 20 条，76.8% 的 star 值与别的卡完全重复，另有 56 条（14.4%）`stars` 为 `None`。

两个后果：

1. `anthropics/skills` 的 17 万星印在它每一个子 skill 上，等于凭空发通行证。
   而且 `log10(1+s)/5` 在万星以上已经饱和——修复前 stock 分项的中位数 0.85、
   p25 高达 0.57，这一项几乎失去区分度。
2. `stars=None` 的 56 条直接拿 0 分，被**系统性压制**（0 vs 中位 0.85，
   乘权重 0.14 就是 0.12 的 G 差距，而 G 的整体标准差只有 0.02）。

**处理方式：按证据强度向中性值收缩，而不是打折到 0。**

```
share  = n^-0.5                       # n = 同仓条目数；1→1.00, 4→0.50, 20→0.22
stock  = neutral + (raw − neutral) · share
```

- **为什么均匀衰减，而不是「让仓库派一个代表拿满分」**：我们并不知道这 20 条里
  是哪一条挣来的星，挑代表等于凭空发明信息。
- **为什么收缩到中性而不是到 0**：一个来自 17 万星精选仓库的 skill 确实比随机仓库
  更可能靠谱，只是我们不知道好多少。这与 CTR 那里「按置信度混合回中性」是同一个形状，
  也是标准的贝叶斯收缩：证据越弱越靠近先验。
- **中性值取仓库级中位数（一仓一票）**：否则拆 20 条的大仓会把中位数拉到自己身上。
- **`stars=None` 自然落位**：`share = 0` → 恰好等于中性，不奖不罚，不再被系统性压制。

增速同理收缩（`vel = 0.25 + (raw − 0.25)·share`）：同仓 20 条记录的是同一份增速轨迹。
`star_history` 的快照本来就按 `full_name` 存，同 key 覆盖，不会膨胀成 20 份；
只是顺手做了去重，省掉 19 次重复写。

**修复效果（真实 388 条，冷启动排序）**

| | 修复前 | 修复后 |
|---|---|---|
| 前 20 条覆盖仓库数 | 14 | **17** |
| 前 20 条单仓最多占用 | 3 | **2** |
| 前 40 条覆盖仓库数 | 16 | **23** |
| 前 40 条单仓最多占用 | 6 | **4** |
| `stars=None` 的 stock | 0.000 | **0.868**（= 仓库级中位数） |

> **一个必须说清的副作用**：修复后 stock 分项的标准差从 0.334 掉到 0.051，
> 这一项对整体排序几乎变成常数偏移。这不是把信号做没了，而是**如实反映了
> 这批语料里 star 的真实信息量**——93.6% 的条目共享继承星数，本来就区分不了。
> 修复前那 0.334 的方差主要来自 `stars=None` 被错误归零造成的人为断层。
> 对真正独立的仓库（10 条），stock 仍然张开在 0.414~1.000（标准差 0.188，
> 折合 0.082 的 G 差距），该区分的地方仍在区分。

### 2.3 新条目保护期

`is_new = (now − first_seen_at) < new_item_grace_days` (默认 3 天) `且 impressions < 200`。

保护期内：
- `ctr_score` 强制取 1.0（中性），不因为没数据被判死
- 享有**探索位里的新品配额**（见 §5），这是真正让它出得来的机制

刻意**不给新条目加分**——加分可以被刷（改个仓库名就重新变新），配额不能。

---

## 3. P(item, device)：个人亲和分

输出 (−1, 1)，`P = tanh(Σ 各维贡献)`。

### 3.1 事件 → 权重

| 事件 | 权重 | 说明 |
|---|---|---|
| `open_github` | **+1.0** | 北极星行为，最强正信号 |
| `useful` | +0.8 | |
| `save` | +0.7 | |
| `dwell_long`（停留 ≥ 8s） | +0.35 | |
| `expand_detail`（展开详情） | +0.3 | |
| `impression_no_action` | −0.05 | 单次很弱，累积起作用，且有上限 |
| `skip_fast`（停留 < 1.5s 且无 open） | **−0.15** | **刻意给小**：这是噪声最大的信号 |
| `not_interested` | −1.0 | 显式，见 §4 |

**`skip_fast` 的两条排除规则（防误判）**

1. 该设备对**同一条目**曾产生过 `open_github` → 本次快速划走**不计负分**（已经转化过，再划走只是看过了）
2. 停留 < **200ms** → **整条事件丢弃**，既不算 skip_fast 也不算曝光。这不是判断，是甩屏，卡片可能都没渲染完

### 3.2 维度与半衰期

亲和度分维累积，每维独立时间衰减（指数）：

| 维度 | 半衰期 | 说明 |
|---|---|---|
| `scene`（一级行业） | 21d | 最稳定的兴趣 |
| `scene_l2`（二级行业） | 14d | |
| `owner`（作者） | 14d | |
| `language` | 30d | 技术栈偏好变得慢 |
| `item` | 90d | 单条记忆，主要用于去重/疲劳 |

衰减在**读取时**算（存 `weight` + `updated_at`，读时乘 `0.5^(Δd/half_life)`），不需要定时任务。

### 3.3 Lookalike（不引 embedding）

对每条候选 i，与设备「正反馈集合 L」（最近 30 天 open_github / useful / save 的条目，取最近 20 条）算相似度：

```
sim(i, j) = 0.40 · [scene_l2 相同]
          + 0.15 · [scene 相同但 scene_l2 不同]
          + 0.25 · jaccard_idf(tokens(i), tokens(j))     # 复用 rank.tokenize + rank.build_df
          + 0.12 · [owner 相同]
          + 0.08 · [language 相同]

lookalike(i) = max_{j∈L} sim(i, j)
```

用 **max 而非 mean**：一个强相关就够了，均值会被 L 里的无关项稀释成噪声。

**明确定位**：lookalike 是**近距离探索**，它让茧房更精致，**不是破圈手段**。
真正防信息孤岛的是 §5 的多样性硬约束 + 15% 探索位。这一点在实现里通过「lookalike 命中的条目**不占**探索位配额」来保证——
探索位只给画像外的内容。

> 💡 **关于要不要上 embedding**（不是拍板项，是我的建议）
> **已裁决：不上。** 成本：`sentence-transformers` 依赖约 90MB 模型 + PyTorch 约 800MB，或走 API（要 key、要每条成本、refresh 时要批量调用、要缓存失效策略）+ 一个向量存储。
> 收益：当前 388 条（将涨到 500+）、已有两级人工 taxonomy，语义结构大部分已被 taxonomy 捕获，剩余部分 IDF-jaccard 覆盖得住。
>
> **🔁 重估触发条件（满足任一即重新评估）**
> 1. 信息流条目总数 **> 5000**
> 2. 单个二级行业（`scene_l2`）占全库比例 **> 15%** —— taxonomy 分辨率饱和的信号
> 3. lookalike 命中率持续 < 5%，说明 IDF-jaccard 在当前语料上已经失效
>
> 触发前不要预先引入向量检索，这个量级下属于过度工程。

---

## 4. N(item, device)：负反馈与疲劳

两件不同的事，都带衰减。

### 4.1 显式「不感兴趣」的作用域阶梯

**客户端必须显式传 `scope`，服务端绝不自行放大作用域。**

| scope | 压制对象 | 初始惩罚 | 半衰期 | 惩罚地板 |
|---|---|---|---|---|
| `item` | 这一条 | 1.0（**硬隐藏**） | 60d | 到期前不出 |
| `owner` | 该作者全部条目 | 0.45 | 30d | −0.05 |
| `scene_l2` | 该二级行业 | 0.30 | 14d | −0.03 |
| `scene` | 该一级行业 | **0.20** | **7d** | −0.02 |

**为什么一级行业惩罚最小、半衰期最短**：它的杀伤半径最大。当前 `engineering` 占 388 条里的 132 条（34%），
一次误点就砍掉三分之一的库存是不可接受的。这直接对应评审里「作用域给宽了会永久杀死品类」。

#### scope 缺失时的降级（重要）

前端「让用户自己选粒度」的交互属于前端那一轮，在它上线之前，
`not_interested` 事件可能**不带 `scope`**。服务端的处理是：

```
scope 缺失 / 为空 / 不在 {item, owner, scene_l2, scene} 之内  →  一律按 item 处理
```

实现在 `ranking_profile.normalize_scope()`，`feedback.py` 与 `server/ranking_service.py`
两条写入路径都过这个函数，没有第二处判断。

**为什么降级到最保守而不是最合理**：猜错的两个方向代价不对称。
按 `item` 处理猜错了，代价只是少推一条；按 `scene` 处理猜错了，
用户会莫名其妙看不到整个品类，而且他根本不知道自己「屏蔽」过什么、更无从撤销。
宁可欠压制，不可过压制。

**额外保险**：除 `item` 级硬隐藏外，**所有 scene/scene_l2/owner 级压制对探索位无效**。
即使用户屏蔽了 `engineering`，探索位仍可能给他一条高质量 engineering——这是有意的解封通道。

#### 修订（会话内回声）：「绝不放大作用域」只约束持久层

上面那条规则单独执行会产生一个新问题：`scope` 降级为 `item` 后，用户点掉一条、
接着往下滑，同类内容照样出现——**当前会话零效果**。一个明确承诺了却不兑现的
反馈按钮，比没有这个按钮更伤信任。

所以在持久层之外加了一层**会话内软压制**（`SessionOrderCache.note_not_interested`）：
命中条目的 `scene_l2` 和 `owner` 各拿一份小惩罚（0.12 / 0.10，同会话累加封顶 0.35），
**只存在进程内存、只活到会话过期、不写库、不跨会话、不参与并档**。

为什么这不违反原规则的意图：原规则要防的是「压错了用户既看不见也撤不掉」。
会话回声的猜错代价上限是半小时，且探索位照旧无视行业级压制。
**一级行业仍然绝不自动放大**——那一层占库存 34%，杀伤半径太大，必须由用户显式选。

作用域 / 衰减 / 即时性三者的取舍：**持久层窄而久，会话层宽而短，
已交付的位置冻结、未交付的立刻重排**（见 §7 修订）。

### 4.2 曝光疲劳

```
fatigue(i,d) = 1 − exp(−no_action_impressions(i,d) / 3)      # 3 次 ≈ 0.63
```
`no_action_impressions` 自身半衰期 3 天（隔几天再看到不算烦）。惩罚权重 `w_fatigue = 0.25`。

**硬规则**：7 天内同一条目累计 **6 次**无动作曝光 → 该设备主 feed **屏蔽该条 7 天**。
对应「同一条不能反复怼」。

---

## 5. F(item, device)：显式关注 + 多样性 + 探索位

### 5.1 F 的取值

- 命中用户显式声明的关注（scene / scene_l2 / 关键词）：**F = 1.0**
- 命中 lookalike（与关注项相似但非直接命中）：**F = 0.45**
- 其余：0

显式关注的置信度**独立于**行为画像置信度：新用户第一次进来就选了「内容创作」，`w_f` 立刻满值。
这是规则 2 与规则 3 不打架的关键（见 §6）。

**主 feed 上限（拍定决策 #3）**：任意 20 卡窗口内，F > 0 的条目最多占 **40%（8 条）**。
顶部动态圆环是独立轨道，不占 feed 槽位，所以「两处都进」成立而主 feed 不被刷屏。

### 5.2 多样性硬约束

排序后做贪心重排，约束如下：

| 约束 | 阈值 | 来源 |
|---|---|---|
| 连续同一级行业 | ≤ 2 条 | 用户建议 |
| 单作者 / 每 20 条 | ≤ 3 条 | 用户建议 |
| 同 scene_l2 / 每 10 条 | ≤ 3 条 | **我加的**：一级太粗，`engineering` 占 34%，只卡一级挡不住同质 |
| F>0 条目 / 每 20 条 | ≤ 8 条 | 拍定决策 #3 |

**算法：带延后队列的贪心**

按分数从高到低走；当前候选违反约束 → 丢进延后队列，取下一个；每填一个位置都先回头重试延后队列。
若所有候选都违反（长尾/筛选后候选池小时必然发生），按固定顺序**逐级放宽**：
`F 上限 → scene_l2 → owner → scene 一级`，而不是丢条目。

**不变量（会写成单测）**：输出集合 == 输入集合，无重复、无丢失。

### 5.3 15% 探索位

每 20 槽固定 3 槽（15%），位置 **5、12、17**（0-indexed）。
避开 0–4 黄金位，但第一个探索位落在首屏可达范围内，保证真的被看见。

**探索池准入**：
- `P(i,d) ≤ 0`，**或** 该条 scene 不在设备 Top-3 亲和行业内
- 且未被 item 级隐藏、未触发疲劳屏蔽
- **忽略** scene/scene_l2/owner 级负反馈压制（见 4.1 的解封通道）

**池内排序**：只按 `G(i)` 排，不带任何个性化。

**新品配额**：每 20 槽的 3 个探索位中，**至少 1 个**必须给 `is_new = true` 的条目（若存在）。
这是新条目真正的出场保证——不是加分，是配额。配额是尽力而为：
只在不破坏多样性约束的前提下优先，不为它放宽约束。

**无画像时不设探索位**：没有「圈内」就无所谓「破圈」，整个 feed 本来就是中立的。
这时候硬标几个探索位只是给用户看不懂的标签。

### 5.4 多样性与探索位必须在同一趟贪心里完成

初版实现是「先跑多样性排好，再把探索条目挪到 5/12/17」。**这是错的**：
从中间抽走一条，原本被它隔开的两条同行业内容会贴到一起，约束当场失效。
真实数据（388 条）验证时首屏出现过连续 4 条同行业。

正确做法是 `arrange_feed()`：从左到右一次成型地填位，
探索位从探索池取、其余位置从主池取，**两者共用同一套约束检查和同一个已填前缀**。

真实数据回归结果（388 条，冷启动与回访各一轮）：
**中段违规 0 次**，唯一超过 2 连的同质段落在最后 2.1% 的位置——
那里候选池只剩一个行业，此时守约束的唯一办法是丢条目，放宽是正确选择。

---

## 6. 仲裁顺序（三条规则如何收敛成一个函数）

### 6.1 权重随置信度连续变化，没有模式切换

```
conf_p = min(1, effective_events(device) / 12)        # 行为画像置信度
conf_f = 1 if device 有显式关注 else 0                 # 显式关注是二值的

w_g = 1.00 − 0.45 · conf_p        # 1.00 → 0.55
w_p = 0.30 · conf_p               # 0.00 → 0.30
w_f = 0.15 · conf_f               # 0 或 0.15
w_n = 1.00                        # 恒定，负反馈任何时候都生效
```

**三条规则的映射**：

| 用户规则 | 落到函数哪一项 | 首次访问 | 回访 |
|---|---|---|---|
| 1. star 降序 × 站内热度交叉 | `G` 里的 velocity + ctr **加权融合**（不是两榜轮流取） | w_g = 1.00，G 独占 | w_g 降到 0.55，仍是最大项 |
| 2. 记住浏览行为 | `P` − `N` | conf_p = 0，P 项为 0 | conf_p 上升，P 逐步接管 |
| 3. 显式关注 + lookalike | `F`（直接命中 1.0 / lookalike 0.45） | 只要选了就立即生效 | 与 P 相加，不互斥 |

**「回访用户 + 有明确关注」的裁决**：不需要裁决——`P` 和 `F` 是**相加**的两项，
一条既符合历史行为又命中显式关注的内容自然拿到 `w_p·P + w_f·F` 双份，排到最前。
这正是原始三条规则「模式化」写法会打架、而加权求和不会的地方。

### 6.2 请求级仲裁顺序（严格优先级）

```
0. 硬过滤    item 级隐藏 / 疲劳屏蔽 / 下架
1. 查询筛选  有 q 或 scene 筛选时：相关性是主排序键，低于阈值直接淘汰
             个性化降级为「相关性同档内（0.1 分桶）的次级排序键」
             具体：w_p ×0.35，w_f ×0.30
             多样性放宽：连续同一级 ≤ 2 放宽到 ≤ 4（搜 "figma" 就该大部分是设计类）
2. 打分      score = w_g·G + w_p·P + w_f·F − w_n·N + ε
3. 排序      score 降序
4. 多样性    带延后队列的贪心重排
5. 探索位    固定位置注入（搜索态下**关闭**探索位——用户在找具体东西，不是在逛）
6. 会话固化  写入会话缓存，分页只做切片
```

**搜索/筛选压过个性化**，这是硬性的。用户主动搜索时的意图强度远高于历史画像。

---

## 7. 会话内排序稳定性

- `session_id` 客户端 sessionStorage 生成，30 分钟无活动过期
- `session_seed = hash(device_id + session_id)`
- 抖动项 `ε(i,s) = 0.02 · (hash(item_id, seed)/2³² − 0.5)`：确定性打破并列，不改变有意义的分差
- **服务端缓存整序**：key = `(device_id, session_id, filter_signature)`，TTL 1800s。
  分页请求只对缓存好的顺序切片，**不重算**。
- CTR 统计和画像在会话开始时**快照**，会话中途不更新

结果：会话内刷新 / 翻页 / 回退，顺序完全一致；新会话才重排。

### 7.1 修订：会话稳定性与「不感兴趣要当场生效」的取舍

这两条直接冲突。取舍是**按位置切开**，而不是二选一：

- `/api/feed` 每次返回时记录该 `(device, session, filter)` 已交付到第几条（`offset+limit` 高水位）
- 收到 `not_interested` 时，把缓存顺序**截断到高水位**：之前的原样保留，之后的丢弃
- 下一次请求时，高水位以内按缓存还原，以外用新画像（含会话回声）重新排

于是：**用户已经滑过的卡一张都不会移位**（「刷新后找不到刚看的那张」不会发生），
**还没看到的部分立刻生效**（下一屏就有感）。

选这个方案而不是「整份缓存作废」：整份作废会把用户已经看过的卡打乱，
而那正是会话缓存存在的唯一理由。也不选「等下个会话再生效」：
用户期待的反馈周期是秒级，等 30 分钟等于没修。

高水位完全由服务端自己知道（它交付过哪些位置），**不依赖前端上报滚动位置**，
所以这条在前端埋点上线之前就已经成立。

---

## 8. 存储设计

### 8.1 服务端（SQLite 新增表）

```sql
-- 匿名设备（登录后并档用）
CREATE TABLE devices (
  device_id   TEXT PRIMARY KEY,        -- 客户端 localStorage 生成的 uuid4
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  user_id     INTEGER,                 -- 登录后回填，未登录为 NULL
  merged_into TEXT,                    -- 并档后指向主设备，形成链
  ua_hash     TEXT
);

-- 原始事件（保留 30 天，用于重算/排障）
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL, session_id TEXT NOT NULL,
  item_key TEXT NOT NULL, action TEXT NOT NULL,
  position INTEGER, position_band INTEGER, dwell_ms INTEGER,
  scene TEXT, scene_l2 TEXT, owner TEXT, source TEXT, scope TEXT,
  ts TEXT NOT NULL, client_ts TEXT,
  UNIQUE(device_id, session_id, item_key, action, client_ts)   -- 重试幂等
);

-- 全站 CTR 汇总（事件入库时增量 UPSERT）
CREATE TABLE item_stats (
  item_key TEXT NOT NULL, position_band INTEGER NOT NULL,
  impressions INTEGER DEFAULT 0, clicks INTEGER DEFAULT 0, opens INTEGER DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (item_key, position_band)
);

-- 设备画像（dim: scene|scene_l2|owner|language|item）
CREATE TABLE device_affinity (
  device_id TEXT NOT NULL, dim TEXT NOT NULL, key TEXT NOT NULL,
  weight REAL NOT NULL, updated_at TEXT NOT NULL,
  PRIMARY KEY (device_id, dim, key)
);

-- 显式关注
CREATE TABLE device_focus (
  device_id TEXT NOT NULL, dim TEXT NOT NULL, key TEXT NOT NULL,
  created_at TEXT NOT NULL, PRIMARY KEY (device_id, dim, key)
);

-- 负反馈压制
CREATE TABLE device_suppress (
  device_id TEXT NOT NULL, scope TEXT NOT NULL, key TEXT NOT NULL,
  weight REAL NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  PRIMARY KEY (device_id, scope, key)
);
```

衰减不用定时任务：存 `weight + updated_at`，读时算 `weight · 0.5^(Δdays/half_life)`。

### 8.2 登录后并档路径

```
POST /api/profile/claim   { device_id }      # 需登录
```

- 该 user 尚无主设备 → `devices.user_id = uid`，此设备成为主设备
- 已有主设备 → 当前设备 `merged_into = 主设备`；
  `device_affinity` 按 weight 相加后重归一，`device_focus` 取并集，
  `device_suppress` 取并集（同 key 取较晚的 `expires_at`）

**为什么保留 `merged_into` 而不是删行**：并档后客户端可能仍用旧 device_id 上报一段时间。
所有读路径统一「顺 `merged_into` 链解析到主设备」，幂等、可重放。

登录能力还没做完，所以现在只落**表结构 + `claim` 接口 + 解析函数**，接口先要求登录态（当前会 401），
登录落地后零改动可用。

### 8.3 本机单用户版

同一个 `ranking.py` 纯函数核心，换适配器：画像与 CTR 都从 `feedback.jsonl` 读（新增 impression 行）。
`ranking.py` 不知道自己跑在哪个后端。

---

## 9. 模块划分与改动清单

| 文件 | 动作 | 内容 |
|---|---|---|
| `ranking.py` | **新建** | 纯函数打分核心：G/P/F/N、Wilson、COEC、lookalike、多样性、探索位、会话种子。**零 IO、零网络、零 DB** |
| `impressions.py` | **新建** | `ItemStats` 结构 + 从 jsonl / SQLite 聚合 + 位置分档 |
| `ranking_profile.py` | **新建** | 设备画像构建、衰减、scope 归一、并档合并逻辑（纯函数） |
| `star_history.py` | **新建** | star 快照读写 + 增速计算（三级降级） |
| `feedback.py` | 改 | 新增 action 与字段；`append_many` 批量落盘；`load_events` 读时归一 action 名 |
| `feed_pack.py` | 改 | `apply_global_scores()` 打 G 分；**新字段进 `KEEP_KEYS`**；新增可选 `data_dir` |
| `rank.py` | 改 | 正负反馈动作表补齐（`open_github` / `not_interested` / `skip_fast` / `save`），旧名 `opened_github` 继续认 |
| `server/db.py` | 改 | 5 张新表 + 读写函数；`insert_events` 逐行插以拿到准确的去重结果 |
| `server/config.py` | 改 | 加载 `config_defaults.json` + 用户 `config.json` |
| `server/ratelimit.py` | **新建** | IP + 设备双维滑动窗口，超限静默丢弃 |
| `server/ranking_service.py` | **新建** | DB ↔ `ranking.py` 的唯一胶水层 + 会话顺序缓存 + 并档 |
| `server/app.py` | 改 | `POST /api/events`、`POST /api/profile/claim`、`GET /api/feed` 接 device_id / session_id / 排序 |
| `config_defaults.json` | 改 | 新增 `ranking` 段 |
| `tests/test_ranking_core.py` | **新建** | 45 用例：打分、CTR、多样性、探索位、会话、搜索优先级 |
| `tests/test_ranking_profile.py` | **新建** | 28 用例：画像衰减、scope、疲劳、并档、曝光聚合、star 快照 |
| `tests/test_ranking_server.py` | **新建** | 19 用例：埋点接口、去重、限流、并档、会话缓存 |

**分层原则**：`ranking.py` 不认识数据库，`server/db.py` 不认识排序，
`server/ranking_service.py` 是唯一的胶水。所以打分逻辑能脱库单测，换存储只动一个文件。
依赖方向 `ranking → rank / scene` 单向，`rank.py` 不得反向 import `ranking.py`（会循环）。

**`KEEP_KEYS` 新增字段**（这个坑已经踩过，明确列出）：
`global_score`、`global_why`、`first_seen_at`、`is_new`、`star_velocity`

---

## 10. 配置项

已加进 `config_defaults.json` 的 `ranking` 段。代码侧（`ranking.DEFAULTS`）保留同样的默认值，
`ranking.resolve_config()` 做深合并，**配置缺任意字段都不会崩**，这条有单测锁定。
用户目录 `~/.skill-feed/config.json` 可再覆盖。

```jsonc
"ranking": {
  "weights": { "global": 1.00, "global_min": 0.55, "personal_max": 0.30, "focus": 0.15, "fatigue": 0.25 },
  "global_parts": { "ctr": 0.34, "velocity": 0.28, "stock": 0.14, "freshness": 0.12, "completeness": 0.12 },
  "ctr": { "prior_alpha": 20, "z": 1.96, "position_bands": [5, 15, 40] },
  "profile": { "confidence_events": 12,
               "half_life_days": { "scene": 21, "scene_l2": 14, "owner": 14, "language": 30, "item": 90 } },
  "dwell": { "skip_fast_ms": 1500, "ignore_below_ms": 200, "long_ms": 8000 },
  "suppress": { "item": [1.00, 60], "owner": [0.45, 30], "scene_l2": [0.30, 14], "scene": [0.20, 7] },
  "fatigue": { "half_life_days": 3, "hard_block_impressions": 6, "hard_block_days": 7 },
  "diversity": { "window": 20, "max_consecutive_scene": 2, "max_owner_per_window": 3,
                 "max_l2_per_10": 3, "max_focus_per_window": 8,
                 "search_max_consecutive_scene": 4 },
  "exploration": { "ratio": 0.15, "slots": [5, 12, 17], "min_new_per_window": 1 },
  "new_item": { "grace_days": 3, "min_impressions": 200 },
  "session": { "order_ttl_s": 1800, "jitter_amp": 0.02 }
}
```

---

## 11. 单测

**结果：161 / 161 通过**（改动前基线 58，本轮新增 103）。全部脱网络、脱库、时间显式注入，无 sleep。

| 测试 | 断言要点 |
|---|---|
| Wilson 低曝光 | 3曝光/2点击 的 `ctr_score` **不高于** 500曝光/60点击；0 曝光返回中性 1.0 |
| COEC 位置去偏 | 同点击数下，band0 曝光的条目得分 **低于** band3 曝光的条目 |
| 负反馈衰减 | scene 级压制 7 天后衰减过半；60 天后 item 级隐藏解除；scene 级永不超过地板 |
| skip_fast 排除 | 曾 open_github 的条目再 skip_fast 不产生负分；<200ms 事件被整条丢弃 |
| 多样性配额 | 连续同一级 ≤ 2；单作者 /20 ≤ 3；**输出集合 == 输入集合**（无丢无重） |
| 多样性放宽 | 候选池全是同一行业时不丢条目，按既定顺序放宽 |
| 探索位 | 每 20 槽恰好 3 个探索位；探索位内容 P ≤ 0 或在 Top3 行业外；至少 1 个新品（若有） |
| 会话稳定 | 同 (device, session) 两次调用顺序完全一致；换 session 顺序改变 |
| 新条目保护 | 0 曝光新条目 ctr 中性、`is_new=true`、拿到探索位新品配额 |
| 搜索优先级 | 有 q 时相关性高但个性化低的条目排在个性化高但相关性低的前面；搜索态无探索位 |
| 三规则收敛 | 回访 + 有关注：双命中条目分数 > 单命中 > 无命中 |
| 并档 | affinity 相加、focus 并集、suppress 取较晚 expires；并档幂等 |
| `KEEP_KEYS` | 新字段真的出现在 `pack_feed` 输出里（防静默丢弃复发） |
| 限流 | 超限静默丢弃且返回 200；同 IP 换设备不连坐；窗口滑过后额度恢复 |
| 埋点去重 | 相同 `client_ts` 重发不重复计数（离线补报场景） |
| 配置兜底 | `ranking` 段缺字段 / 整段缺失都不崩 |

**多样性断言的正确写法**：约束是「只要还有别的可选就必须遵守」，不是「任何情况下都成立」。
候选池被筛到只剩一个行业时，硬守约束的唯一办法是丢条目，那更糟。
所以测试断言都带「当时还有替代品」的前提，另配一组直接测 `_violates()` 的用例锁死约束本身。
第一版测试就是因为造了「20 条全是同一行业」的数据而误报失败。

现有用例保持全绿。`rank.rerank()` 未改签名与产出字段，
`personal_score` 沿用「最终排序分」的旧语义（前端和既有测试都依赖它），
新增的 P 分量另起名 `affinity_score`，避免语义漂移。

---

## 12. 服务端安全

### 12.1 限流不能被一行请求头绕过

`_client_ip()` 曾经无条件读 `X-Forwarded-For` 首段——而**首段是客户端自己写的**，
伪造一行头就能换一个限流桶，配合客户端自铸的 device_id，整套双维限流形同虚设。

但在反向代理后面又必须读它，否则全站请求都来自代理 IP、共用一个桶。所以要
**两个条件同时成立**才读：

1. **socket 对端在受信代理名单里**（`SKILLFEED_TRUSTED_PROXY_IPS`）。
   只看链长度不够——「客户端直连并伪造一段」和「Nginx 追加了一段」都是长度 1，分不开。
2. **取从右往左第 N 跳**（`SKILLFEED_TRUSTED_PROXY_HOPS`）。
   Nginx 的 `$proxy_add_x_forwarded_for` 把它实际看到的地址追加在最右边。

| 部署形态 | HOPS | IPS |
|---|---|---|
| 本地 / 直连（**默认**） | 0 | 空 |
| 阿里云轻量 + 同机 Nginx | 1 | `127.0.0.1` |
| CDN → Nginx 两层 | 2 | Nginx 出口地址 |

⚠️ 默认值和生产值不同，这是最容易踩的坑。只配 HOPS 不配 IPS 无效（有意为之：
没有可信对端就无法判断请求是否真的走过代理）。

### 12.2 device_id 归属：服务端签发凭据

`/api/profile/claim` 过去只校验登录态，不校验 device_id 是不是调用方的——
知道他人 device_id 就能把他的匿名画像并进自己账号，而且 `merged_into` 会把
受害者后续请求也导向攻击者的画像，等于接管了他的个性化。

**方案**：服务端在**首次**见到某个 device_id 时下发一枚 HMAC 凭据
（`device_token = HMAC(session_secret, "device:"+device_id)`），之后不再补发；
claim 时校验。

- 攻击者知道 device_id 也拿不到凭据（只在注册那一次返回过），伪造 HMAC 需要密钥
- 抢在受害者之前用他的 device_id 注册，需要先猜中一个尚未使用的 uuid4，不构成现实威胁
- 顺带把 device_id 从 query 挪到 `X-Device-Id` 头：query 会进 access log 和 Referer

### 12.3 会话密钥 fail-closed

`session_secret` 的缺省值曾是写死在本仓库里的 `"dev-only-change-me"`，
等于任何人都能自签 cookie 冒充任意用户（评审实测：不登录即可读他人帖列表、以他人身份发帖）。

现在：缺 `SKILLFEED_SESSION_SECRET` 时**拒绝启动**；本地开发设 `SKILLFEED_DEV=1`
才会随机生成临时密钥，并在启动日志里说明「重启后所有登录态失效」。
已公开过的几个常量进了黑名单，显式设成它们也会被拒。

`create_app()` 做这个检查而不是 `Settings()`，且模块级 `app` 改成 PEP 562 惰性构建——
否则 `import server.app` 都会炸，测试和工具脚本连带失败。

### 12.4 无凭据登录 fail-closed

`/auth/github` 过去在 OAuth 未配置且 `dev_auth=1` 时会 302 到 `/auth/dev-login`，
而那条路由不校验任何凭据就发 30 天会话。**接微信登录的改造期漏配一个环境变量，
站点就变成「点一下就登进去」**。

- `/auth/github`：OAuth 未配置一律 503，**不再静默降级**
- `/auth/dev-login`：要求 `SKILLFEED_DEV=1` **且** `SKILLFEED_DEV_AUTH=1` **且** 站点非 https。
  漏配只会让它更严，不会打开它
- `github_id` 不再硬编码为 1（那会让所有 dev 登录复用同一行 users，
  一个 GET 就能改掉用户名；而且 1 是合法的真实 GitHub id，可能撞真人账号）。
  改成由 login 经 blake2b 派生的**负数**，与真实 id 空间不相交

### 12.5 CSP 与安全响应头

所有响应带 `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、
`Referrer-Policy: no-referrer`（后者顺带堵住 device_id 经 Referer 外泄）。

| 响应类型 | CSP |
|---|---|
| JSON / API | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'` |
| HTML 页面 | `script-src 'self' 'nonce-<每次请求随机>'` + `object-src 'none'` + `base-uri 'self'` + `form-action 'self'` |

`style-src` 保留 `'unsafe-inline'` 是**有意的取舍**：模板里有 `style="display:none"`
这类内联属性，CSP 的 nonce 只作用于 `<style>` 元素、不作用于 style 属性，
强上 nonce 会直接白屏。样式注入无法执行脚本，风险等级远低于 script。
`script-src` 才是这条策略的主要目的，它是严格的。

#### 静态产物的 CSP（已补，此前是本台账里唯一还没修的 P0）

上面那张表管的是 FastAPI 的响应头。但**线上真正被访问的那份页面不经过它**：
`index.html` / `embed.html` 由 GitHub Pages 直接吐给浏览器，服务端响应头够不着，
所以那份产物长期处于「无 CSP」状态——而这件事本身还写在公开仓库里。

现在由 `feed_dashboard._with_csp()` 在生成时把策略写进
`<meta http-equiv="Content-Security-Policy">`。三个和上表不同的取舍：

**用哈希，不用 nonce。** 静态文件每次响应给的是同一份字节，写死的 nonce
对攻击者和对我们一样可见，等价于 `'unsafe-inline'`。nonce 只在动态响应里成立。

**`script-src` 是严格的**：只有那一块内联 script 的 `sha256`，没有 `'unsafe-inline'`、
没有 `'unsafe-eval'`、没有 `'self'`。全站没有外链脚本，也没有 `eval` /
`new Function` / 字符串式 `setTimeout`（改动前逐条核查过），所以收得这么紧。
代价是封面图那个内联 error 属性得改掉——哈希覆盖不到属性，它在这条策略下会
静默失效，已改成 `document` 上捕获阶段的委托监听（`error` 事件不冒泡）。

**`style-src` 分三档下发**，比上表更细：

| 指令 | 取值 | 为什么 |
|---|---|---|
| `style-src-elem` | `sha256` + `fonts.googleapis.com` | 内联 `<style>` 收紧到哈希 |
| `style-src-attr` | `'unsafe-inline'` | 模板里 19 处 `style=""`，哈希覆盖不到属性 |
| `style-src` | `'unsafe-inline'` + 字体域 | **老浏览器的回退档，必须留** |

最后一行是关键：`style-src-elem` / `-attr` 是 Chrome 75 / Firefox 111 /
Safari 15.4 以后才有的，不支持的浏览器会回退到 `style-src`——那里如果不留
`'unsafe-inline'`，内联 `<style>` 会被一起拦掉，整页变成无样式的裸 HTML。
宁可在老浏览器上少一层 CSS 防护，也不能让页面在那里彻底不可读。

`img-src` 放到 `https:` 这么宽，是因为封面图地址来自陌生人的仓库元数据，
收窄到白名单会让相当一部分卡片没有封面。

`frame-ancestors` 没法写进 meta（规范不支持），但 `embed.html` 本来就是给人嵌的，
不需要限制。

验证方式见 `tests/test_feed_dashboard.py::TestContentSecurityPolicy`：那里从
**最终 HTML** 重新抠出内联块自己算哈希再比对，而不是复用被测代码的中间变量——
后者两边一起错也照样绿。哈希错一个字节的后果是整页白屏，这条测试是它的唯一防线。

---

## 13. 埋点接口限流

**为什么这不是可选项**（且必须配合 §12.1 的代理信任才有意义）：规则 1 明确依赖「本站用户点得最多的 skills」，
也就是 CTR 直接决定首页顺序。一个匿名可写、无限流的 `/api/events`
等于把首页排序的写权限公开——刷几百次曝光 + 点击就能把任意条目顶上去。

| 维度 | 默认阈值 | 说明 |
|---|---|---|
| 窗口 | 300s 滑动窗口 | |
| 单 IP | 600 事件 / 窗口 | |
| 单设备 | 400 事件 / 窗口 | 同 IP 下换设备不连坐，办公室共用出口 IP 的场景不误伤 |
| 单请求 | 200 事件 | 超出直接截断 |

**超限静默丢弃，仍返回 200。** 返回 429 等于告诉刷量的人阈值在哪，方便他二分试探；
静默丢弃让他拿不到反馈信号。正常用户永远碰不到这个阈值，所以静默不伤体验。

实现是进程内滑动窗口（`server/ratelimit.py`），不引 Redis：单实例部署够用，
多实例时每实例各算各的、实际阈值放大 N 倍，仍在可接受范围。要精确再换。

---

## 14. 裁决记录（已全部拍板）

| # | 事项 | 结论 |
|---|---|---|
| 1 | star 快照写盘路径 | **A：`star_history.py` 自解析目录**。B 更正派但需跨 agent 协调 `skillfeed.py`，代价更高。取舍写进模块 docstring |
| 2 | `config_defaults.json` 新增 `ranking` 段 | **加**。代码侧仍有完整兜底，配置缺字段不崩（已单测） |
| 3 | 探索位固定 5/12/17 | **固定**。可预测、可测、便于归因 |
| 4 | 一级行业负反馈 0.20 / 7 天 | **采纳**。用户点「不感兴趣」的真实意图通常针对那一条，压太狠会误伤；值已进配置段，看数据再调 |
| 5 | 是否引入 embedding | **不引**。重估触发条件见 §3.3 |
| 6 | `/api/events` 限流 | **本期就加**，见 §12。CTR 决定首页顺序，等于排序写权限 |
```
