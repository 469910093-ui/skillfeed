# skill-feed 前端埋点事件契约

状态：**待评审**（正文为 v1；**v1 有 5 处会导致上线即失败的缺口，修订见文末 §8**）
配套文档：`docs/ranking-engine-design.md`
读者：负责前端埋点实现的 agent / 开发者

> ⚠️ **动手前先读 §8。** v1 正文里所有 `/api/events`、`/api/feed` 都写成了站内相对路径，
> 而线上主力形态是 GitHub Pages 静态站，那个源站上没有任何 `/api/*`。
> 照 v1 实现一遍，结果和现在完全一样：请求 404、信号全丢、没人发现。

排序引擎的 CTR、停留时长、会话稳定性全部依赖这份契约。**契约里没有的字段，服务端一律忽略；契约里有但没上报的，对应能力静默降级。**

---

## 1. 两个 ID：设备与会话

| ID | 存储 | 生成 | 过期 |
|---|---|---|---|
| `device_id` | `localStorage["skillfeed_did"]` | 首次访问生成 `crypto.randomUUID()` | 永不主动清除 |
| `device_token` | `localStorage["skillfeed_dtok"]` | **服务端下发**，见下 | 与 device_id 同生命周期 |
| `session_id` | `sessionStorage["skillfeed_sid"]` | 每个标签页会话生成 `crypto.randomUUID()` | **30 分钟无活动**后重新生成 |

### device_id 走请求头，不走 query

```
X-Device-Id: <device_id>
```

`/api/feed?device_id=...` 仍然兼容，但**不要用**：query 会被写进 Nginx access log，
也会经 Referer 泄漏给第三方，等于把「劫持匿名画像所需的那半个凭据」到处散播。

### device_token：服务端签发的设备凭据

device_id 是客户端自铸的，服务端无法凭它判断归属。所以：

1. 服务端**首次**见到某个 device_id 时，在 `/api/events` 或 `/api/feed` 的响应里
   返回一次 `device_token`（HMAC 签名，客户端伪造不了）
2. 客户端收到就存进 `localStorage`，**之后不会再下发**
3. 登录后调 `/api/profile/claim` 并档时必须带上它，否则 403

```js
const res = await fetch("/api/events", { /* … */ });
const data = await res.json();
if (data.device_token) localStorage.setItem("skillfeed_dtok", data.device_token);
```

没有这一步，任何人只要知道你的 device_id 就能把你的匿名画像并进他的账号
（并且后续你的请求会被导向他的画像）。

「无活动」= 无 scroll / click / visibilitychange。前端需自行维护 `last_active_ts`，
在下一次要发事件时若 `now - last_active_ts > 30min`，先换新 `session_id` 并补发一条 `session_start`。

> **为什么 session_id 这么关键**：服务端按 `(device_id, session_id, filter_signature)` 缓存整个排序结果。
> 同一 session 内刷新/翻页返回完全相同的顺序，用户不会「刷新后找不到刚才那张卡」。
> session_id 乱变 = 顺序乱跳。

`device_id` 每个请求都要带（feed 请求走 query param，事件请求走 body）。**不要放进 cookie**，避免与登录会话 cookie 混淆。

---

## 2. 事件总表

所有事件共有字段：

```jsonc
{
  "action":     "impression",              // 见下表
  "item_key":   "hardikpandya/stop-slop::SKILL.md",  // 用 feed item 的 id 字段原样回传
  "client_ts":  "2026-09-03T16:42:01.123Z", // 客户端时间，ISO8601，毫秒精度
  "position":   7,                          // 该卡在当前 feed 里的 0-indexed 位置
  "scene":      "content",                  // 从 feed item 原样回传
  "scene_l2":   "writing",
  "owner":      "hardikpandya",
  "source":     "hellogithub"
}
```

`client_ts` 参与服务端去重（`device_id + session_id + item_key + action + client_ts` 唯一），所以**重试必须复用原始 client_ts**，不能重新取时间。

| action | 触发时机 | 额外字段 | 排序引擎里的用途 |
|---|---|---|---|
| `session_start` | 会话建立 / 换新 session_id | `referrer`, `landing`, `utm_source`, `utm_medium`, `utm_campaign`, `channel`（可选 hint；服务端会再归类）, `viewport_w`, `viewport_h` | 会话计数（北极星分母）+ **渠道归因**（SEO/GEO/社交/直接等）；服务端把首触渠道写入 `devices`（只写一次） |
| `impression` | 卡片 **≥50% 可见持续 ≥300ms** | — | CTR 分母、疲劳计数 |
| `dwell` | 卡片离开视口时 | `dwell_ms` | 长停留正信号 / 快速划走负信号 |
| `open_github` | 点击「打开 GitHub」CTA | — | **北极星行为**，CTR 分子，最强正信号 |
| `useful` | 点「有用」 | — | 正信号 |
| `save` | 点「收藏」 | — | 正信号 |
| `expand_detail` | 展开卡片详情 / 查看 SKILL.md | — | 弱正信号 |
| `not_interested` | 点「不感兴趣」 | **`scope`**（必填） | 负反馈，见 §4 |
| `focus_set` | 顶部动态圆环关注项变更 | `focus`（数组） | 显式关注权重 |

### 2.1 `impression` 的精确定义

用 `IntersectionObserver`，`threshold: 0.5`。进入 ≥50% 可见后**启动 300ms 计时器**；
若 300ms 内跌破 50%，取消计时器、**不上报**。这道门槛过滤甩屏。

同一卡片在同一 session 内**反复进出视口只上报一次 impression**（前端维护 `Set<item_key>`）。
否则来回滚动会把 CTR 分母灌爆。

### 2.2 `dwell` 的精确定义

`dwell_ms` = 卡片 ≥50% 可见的**累计毫秒数**，不是首末时间差。

必须做的两件事：
1. `document.visibilityState === "hidden"` 时**暂停计时**（切标签页、锁屏不算在看）
2. 卡片离开视口时上报一次；若用户一直没滚走，在 `beforeunload` / `visibilitychange→hidden` 时补发

服务端据此判定：
- `dwell_ms < 200` → **整条事件丢弃**（不是负信号，是甩屏，卡片可能都没渲染完）
- `dwell_ms < 1500` 且本卡无 `open_github` → 记为 `skip_fast`（弱负信号）
- `dwell_ms ≥ 8000` → 记为 `dwell_long`（正信号）

阈值判定在**服务端**做，前端只如实上报 `dwell_ms`。这样调阈值不用发前端版本。

---

## 3. 上报端点

### `POST /api/events`

```jsonc
// Request  （device_id 建议放 X-Device-Id 头，body 里的字段是兼容路径）
{
  "device_id": "b0f1…",
  "session_id": "9ac3…",
  "events": [ { /* 事件对象 */ }, … ]     // 单请求最多 200 条，超出服务端截断
}

// Response 200
{ "ok": true, "accepted": 18, "deduped": 2,
  "device_token": "…" }                   // 仅首次注册该 device_id 时出现
```

- 无需登录，匿名可写
- `Content-Type: application/json`
- **响应永远不影响页面渲染**，前端不得 await 它来决定 UI
- 出现 `device_token` 就存下来（见 §1）

### 限流

按 IP 和设备各一道滑动窗口（默认 5 分钟内 600 / 400 条）。
**超限不报错，返回 200 但静默丢弃**——返回 429 等于告诉刷量的人阈值在哪。
正常用户碰不到这个阈值；如果你的埋点实现能触发它，说明上报太密了，请调大批量间隔。

### 批量与节流策略

内存缓冲，满足任一条件即 flush：
- 距上次 flush **≥ 5 秒**
- 缓冲区累计 **≥ 20 条**
- `visibilitychange → hidden`（**必须用 `navigator.sendBeacon`**，普通 fetch 在页面隐藏时会被浏览器杀掉）
- 用户触发 `open_github`（高价值事件，**立即 flush**，不等 5 秒——用户可能马上就跳走了）

### 失败降级

1. 网络失败 → 事件回写 `localStorage["skillfeed_evq"]` 环形缓冲，**上限 500 条，超出丢最旧**
2. 下次 flush 时优先带上积压事件，指数退避重试（5s → 10s → 20s → 40s，封顶 60s）
3. 连续失败 10 次 → 停止上报直到下次 `session_start`（避免离线时空转耗电）
4. `localStorage` 不可用（隐私模式）→ 内存降级，`device_id` 退化为会话级，画像失效但功能不受影响

**核心原则：`/api/events` 挂掉，feed 必须照常能刷。** 此时服务端退化到 build 期的全局排序 `G`。

---

## 4. `not_interested` 的 scope（重要）

`scope` **必填**，取值 `item` | `owner` | `scene_l2` | `scene`。

**UI 必须让用户自己选，前端不得替用户放大作用域。** 建议交互：点「不感兴趣」弹二级选择——

```
不感兴趣
  ├─ 就这一条                    → scope: "item"
  ├─ 不看 hardikpandya 的        → scope: "owner"
  ├─ 不看「写作润色」             → scope: "scene_l2"
  └─ 不看「内容创作」整个行业      → scope: "scene"
```

默认高亮「就这一条」。压制强度和衰减各不相同（见设计文档 §4.1）：
一级行业压制刻意做得最轻、衰减最快，因为它一次能砍掉库里三分之一的内容。

```jsonc
{ "action": "not_interested", "item_key": "…", "scope": "owner", "client_ts": "…", … }
```

---

## 5. `focus_set`

动态圆环选择变更时**全量上报当前关注集**（不是增量 diff，避免状态不同步）：

```jsonc
{
  "action": "focus_set",
  "client_ts": "…",
  "focus": [
    { "dim": "scene",    "key": "content" },
    { "dim": "scene_l2", "key": "writing" },
    { "dim": "keyword",  "key": "figma"   }
  ]
}
```

空数组 `[]` 表示取消全部关注，合法。

---

## 6. Feed 请求

### `GET /api/feed`

| 参数 | 必填 | 说明 |
|---|---|---|
| `device_id` | 是 | 无则退化为纯全局排序 |
| `session_id` | 是 | 无则每次请求重排，顺序会跳 |
| `limit` / `offset` | 否 | 分页，服务端从会话缓存切片 |
| `q` | 否 | 搜索词，**存在时相关性压过个性化，且关闭探索位** |
| `scene` / `scene_l2` | 否 | 行业筛选，同上 |
| `source` | 否 | `all` / `ugc` / `official` |

**`q` / `scene` / `scene_l2` 任一变化都会改变 `filter_signature`，服务端重新计算并缓存一份新顺序。**
这是设计内的：换了筛选条件，顺序本来就该变。

### 响应新增字段

```jsonc
{
  "items": [ { …, "rank_slot": "main" | "exploration", "rank_debug": "g:0.62 p:+0.18 f:0 n:-0.05" } ],
  "session_id": "9ac3…",        // 服务端回显（若前端没传会代生成，前端应存下来）
  "ranking_mode": "personalized" | "global" | "search"
}
```

`rank_debug` 仅在 `?debug=1` 时返回，用于排障与人工复核，不要展示给普通用户。

---

## 7. 前端自检清单

实现完成后逐条验：

- [ ] 快速甩屏滚过 50 张卡 → 上报的 `impression` 数远小于 50（300ms 门槛生效）
- [ ] 同一卡来回滚动 5 次 → 只有 1 条 `impression`
- [ ] 切到别的标签页 30 秒再切回 → `dwell_ms` 没有增加 30000
- [ ] 点 CTA 后立刻关页面 → `open_github` 仍然到达服务端（sendBeacon 生效）
- [ ] 断网操作一轮再联网 → 积压事件补报成功，且没有重复计数（client_ts 复用）
- [ ] 页面内刷新 → feed 顺序完全不变
- [ ] 等 31 分钟后操作 → 新 session_id + 新 `session_start`，顺序允许变化
- [ ] `/api/events` 返回 500 → 页面无任何可见异常，feed 照常刷
- [ ] 隐私模式（localStorage 禁用）→ 不报错，功能降级但可用

---

## 8. v2 修订（服务端已按本节实现）

v1 是在「前端埋点还没做」的假设下写的，落到真实前端上有 5 处会直接失败。
以下为准，与正文冲突时以本节为准。

### 8.1 端点必须走 `api_base`，不能用相对路径 ⬅ 这是当前 bug 的根因

产品有两种部署形态，v1 只考虑了后者：

| 形态 | 页面来源 | `/api/*` 是否存在 |
|---|---|---|
| GitHub Pages 静态站（**主力**） | `feed.html`，纯静态 | **不存在**，同源 404 |
| 自建 FastAPI 站 | `server/app.py` | 存在 |
| 本机 `python skillfeed.py serve` | 127.0.0.1:8473 | 只有旧的 `/api/feedback` |

页面里已经有现成的机制：`FEED.ui.api_base`（由 `SKILLFEED_PUBLIC_URL` 在 build 时写入），
`apiUrl(path)` 会拼出绝对地址。**所有埋点请求都必须走 `apiUrl('/api/events')`。**
`api_base` 为空（未配置云端）时，直接**不上报**并跳过整套埋点，不要退回相对路径——
退回相对路径就是现在这个 bug。

跨源上报要注意两点：服务端 CORS 白名单（`SKILLFEED_CORS_ORIGINS`）要含 Pages 域名；
`sendBeacon` 跨源只能发 `text/plain` 或 `Blob`，用 `new Blob([json], {type:'application/json'})`。

### 8.2 `useful` 和 `save` 是两个事件，不能都发 `useful`

当前前端的心形（点赞）和书签（收藏）在 `toggleLike` / `toggleSave` 里**都调了
`sendFeedback('useful')`**，后端因此只看到一个信号。两者语义和权重都不同：

| UI 动作 | `action` | 画像权重 | 理由 |
|---|---|---|---|
| 点「打开 GitHub」 | `open_github` | 1.00 | 北极星行为 |
| 点书签（收藏） | `save` | **0.90** | 「我以后要用」——一次延迟的打开，指向未来行动 |
| 点心形 / 双击卡片（点赞） | `useful` | **0.45** | 「这个不错」——零成本、可被双击手势误触，量级天然大 |

取消点赞 / 取消收藏**不要**上报（没有对应的负向 action）。

### 8.3 条目级动作必须带 `item_key`

`session_start` 和 `focus_set` 之外的所有动作，缺 `item_key`（或 `full_name`）
一律拒收，计入 `rejected_by_reason.missing_item_key`。
`item_key` 用 feed item 的 `id` 字段原样回传，不要自己拼。

### 8.4 响应新增自查字段

```jsonc
{ "ok": true, "accepted": 18, "deduped": 2,
  "rejected": 3,
  "rejected_by_reason": { "fling": 2, "missing_item_key": 1 },
  "device_token": "…" }
```

`rejected_by_reason` 的取值：`not_a_dict` / `unknown_action` / `missing_item_key` /
`fling` / `ratelimited` / `truncated`。

联调时**盯着这个字段**：字段名拼错、`action` 写错、`item_key` 忘带，
都会在这里直接显形，不用去翻服务端日志。稳态下它应该只剩 `fling`
（甩屏是正常现象）。`ratelimited` 出现说明上报太密，调大批量间隔。

### 8.5 `not_interested` 的 `scope` 可以先不做

v1 §4 写的是 `scope` 必填。服务端已实现缺省降级为 `item`（最保守的粒度），
所以**二级选择 UI 可以延后**，先发不带 `scope` 的事件也能工作。

但要知道服务端此时做了什么：持久层只压这一条，同时在**会话内存**里加一层
更宽的软压制（该条目的 `scene_l2` + `owner`），只活到会话过期。
所以「已记下，之后少推这类」这句 toast 从这一版开始是**真的**——
用户接着往下滑就会看到变化。二级选择 UI 做出来之后，显式 `scope`
会取代猜测，效果更准。

### 8.6 「我的」面板的数据源

```
GET /api/profile/reactions
  Header: X-Device-Id, X-Device-Token   ← 两个都必须带，缺凭据 403
  Query:  limit（可选，默认 200）

200 { "ok": true, "device_id": "…",
      "liked":  [ { item_key, scene, scene_l2, owner, language, source, ts } ],
      "saved":  [ … ],
      "opened": [ … ] }
```

要 `X-Device-Token` 是因为 `device_id` 是客户端自铸的：只凭它就能读，
等于知道别人的 `device_id` 就能翻他的浏览记录。凭据就是首次注册时下发、
存在 `localStorage["skillfeed_dtok"]` 的那一枚，与 `/api/profile/claim` 同一个。

面板至少要展示 `liked` 和 `saved` 两个分组（不要合并成一个「我的收藏」，
那等于在 UI 上把刚拆开的两个信号又粘回去），每条给出卡片标题 + 打开 GitHub 的入口。
本地 `localStorage` 里已有的点赞/收藏集合与服务端返回取并集，
服务端为准——换设备后本地是空的，服务端才有历史。

### 8.7 服务端摄入健康（联调与线上巡检）

```
GET /health                 公开。events_total / last_event_age_s / ingest_stale
GET /api/events/health      需登录态或 X-Metrics-Token。含 rejected_by_reason 与限流命中数
```

联调时打一次 `/health`：`events_total` 不涨就说明请求根本没到，
不用再猜是前端还是后端。线上把 `ingest_stale` 接进探针，
「链路断了一个多月没人发现」这件事不该再发生第二次。
```
