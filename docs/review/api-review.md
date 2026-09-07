# skill-feed / skillfeeder API 只读评审

| 项 | 值 |
|---|---|
| 评审范围 | `server/`（FastAPI）全部路由 + `skillfeed.py serve` 本地 HTTP 处理器 + 出站依赖（GitHub API / raw / 百炼 LLM） |
| 代码读取时间点 | **2026-09-03 16:46 (UTC+8)**，`git rev-parse HEAD` = `10465b8e6466bb8e2056af89566f26f2385da5b6`，工作区含未提交改动（`server/` 下**无**未提交改动，`git status` 未列出 `server/*`） |
| 探测时间点 | 2026-09-03 16:49–17:05 (UTC+8) |
| 探测方式 | `python -m uvicorn server.app:app --host 127.0.0.1 --port 8611`（另起一实例在 8613 验证 CORS/Cookie 变体）。**未使用 `skillfeed.py serve`** |
| 数据隔离 | `SKILLFEED_DB` / `SKILLFEED_HOME` 指向 `%TEMP%\skillfeed-apireview`，未写入 `~/.skill-feed/` |
| 上游隔离 | `SKILLFEED_OFFICIAL_FEED_URL` 指向本地计数桩（127.0.0.1:8612），**未对 skillfeeder.cn / GitHub Pages 发起任何探测或压测** |
| 代码改动 | **零**。本文件为唯一新增产物；临时探测脚本已删除 |

> ⚠️ 排序引擎 agent 也在改 `server/`。本文所有行号基于上述时间点的工作区快照，若 `server/` 已被改动请以行号附近的代码内容为准。**本次评审未修复任何问题。**

---

## 1. 接口清单与契约

### 1.1 OpenAPI 可用性

FastAPI 默认文档**全部开着且无鉴权**：

```
GET /openapi.json  -> 200 (6783 bytes)
GET /docs          -> 200 (Swagger UI)
GET /redoc         -> 200 (ReDoc)
```

`server/app.py:38-42` 创建 app 时未传 `openapi_url=None` / `docs_url=None`，也没有任何 gating。见 SEC-10。

### 1.2 路由全表

`ROOT = server/app.py`。`/static` 挂载条件为 `(ROOT/"static").exists()`，当前该目录不存在，故未挂载（`app.py:53-55`）。

| # | 方法 | 路径 | 入参（来源） | 鉴权 | 成功响应 | 实测错误码 | 定义位置 |
|---|---|---|---|---|---|---|---|
| 1 | GET | `/health` | — | 无 | `{ok, oauth, dev_auth, official_feed}` 全为 bool | — | `app.py:57-64` |
| 2 | GET | `/` | — | 无 | `text/html`（`templates/home.html` 原样） | — | `app.py:66-69` |
| 3 | GET | `/publish` | cookie `skillfeed_session`（可选） | 无（未登录也返回页面，仅切换前端 gate） | `text/html`，模板内 `{{logged_in}}`/`{{public_url}}` 被字符串替换 | — | `app.py:71-77` |
| 4 | GET | `/auth/github` | — | 无 | 302 → GitHub authorize；`Set-Cookie: skillfeed_oauth_state`（HttpOnly, Max-Age=600, SameSite=lax） | 503（未配 OAuth 且 `dev_auth=0`，**detail 里回显环境变量名**）；**302 → `/auth/dev-login`（未配 OAuth 但 `dev_auth=1`）** | `app.py:80-92` |
| 5 | GET | `/auth/callback` | query `code`(str, 默认"")、`state`(str, 默认"")；cookie `skillfeed_oauth_state` | 无 | 302 → `/publish`，`Set-Cookie: skillfeed_session` | 400 `missing code`；400 `bad oauth state`；**500（state 与 cookie 自洽但 OAuth 未配 / GitHub 换 token 失败时未捕获异常）** | `app.py:94-113` |
| 6 | GET | `/auth/dev-login` | query `login`(str, 默认`dev-user`，被 `[:39]` 截断) | 无 | 302 → `/publish` + 会话 cookie | 404 `dev auth disabled`（`dev_auth=0` 时） | `app.py:115-129` |
| 7 | POST | `/auth/logout` | — | **无**（未登录调用也 200） | `{"ok": true}` + 清 cookie | — | `app.py:131-135` |
| 8 | GET | `/auth/me` | cookie（可选） | 无 | `{user: {id, login, avatar_url, name}\|null, oauth, dev_auth}` | — | `app.py:137-148` |
| 9 | GET | `/api/feed` | query `limit`(int, 1–100, 默认40)、`offset`(int, ≥0, 默认0)、`source`(`all\|ugc\|official`, 默认`all`) | 无 | `{items[], ugc_count, official_count, generated_mode:"api-merge", me:null}` | 422（limit/offset/source 越界或类型错） | `app.py:151-190` |
| 10 | POST | `/api/posts` | body JSON `PostCreate{title, body_md, github_url, description}`，全部 `str` 默认 `""` | **需登录**（cookie） | `{ok:true, post:{…全表字段}, feed_item:{…}}` | 401 `login required`；400（业务校验，中文 detail）；422（字段类型错）；**500（session uid 指向不存在的用户 → FK 约束失败）** | `app.py:193-207` |
| 11 | POST | `/api/posts/form` | **form** `title/body_md/github_url/description` | **需登录** | 303 → `/publish?ok=1` | 401；400 | `app.py:209-226` |
| 12 | GET | `/api/posts/me` | cookie | **需登录** | `{posts:[…原始 DB 行，含 author_id/body_md 全文…]}` | 401 | `app.py:228-233` |
| 13 | POST | `/api/posts/{post_id}/react` | path `post_id`(int)；body `ReactBody{kind: ^(like\|save\|bad)$, on: bool=true}` | **需登录** | `{"ok": true}` | 401；404 `post not found`（含负数 id）；422（kind 非法/缺失、on 类型错、post_id 非整数）；**500（post_id ≥ 2^63，`OverflowError: Python int too large to convert to SQLite INTEGER`）** | `app.py:235-243` |

**旁路：`skillfeed.py serve` 的本地 HTTP 处理器**（`skillfeed.py:815-858`），仅绑 `127.0.0.1`，单用户本机形态：

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/`、`/feed.html`、`/index.html` | 无 | 回 `feed.html` 字节流 |
| GET | `/feed.json` | 无 | 回 `feed.json` 字节流 |
| GET | `/api/feedback` | 无 | `feedback.summarize()`，**返回最近 50 条完整反馈行** |
| POST | `/api/feedback` | 无 | `feedback.append_feedback()` 追加 `~/.skill-feed/feedback.jsonl` |

该处理器无 CORS 头、无 CSRF token、无大小限制（`Content-Length` 直接 `int()` 后全量 `read`）。因为只绑回环地址，风险等级压到 P2（见 FN-07）。**注意：线上多用户站点没有 `/api/feedback`，说明「反馈上报」目前只存在于本机形态，尚未上云。**

### 1.3 数据模型（`server/db.py:11-52`）

```
users     (id PK AUTOINCREMENT, github_id INTEGER NOT NULL UNIQUE, login, avatar_url, name, created_at)
posts     (id PK, author_id FK→users.id, title, body_md, description, github_url, full_name,
           scene, scene_l2, scene_label, scene_l2_label, cover_url,
           status DEFAULT 'published', created_at, updated_at)
reactions (user_id, post_id, kind, created_at, PRIMARY KEY(user_id, post_id, kind))
```

无 `deleted_at`、无审核态（除 `status` 字段但没有任何写路径把它设成非 `published`）、无 `reactions` 聚合读接口、无索引覆盖 `posts.author_id`。

---

## 2. 安全发现（按可利用性排序）

### SEC-01 · P0 · 默认 session 密钥可预测，任何人可伪造任意用户身份

**证据（代码）** `server/config.py:22`

```python
self.session_secret = _env("SKILLFEED_SESSION_SECRET") or "dev-only-change-me"
```

会话是无状态 HMAC-SHA256 签名 JSON（`server/auth.py:32-53`），载荷只有 `{"uid", "login", "exp"}`。密钥缺省即 `dev-only-change-me`，且该常量在公开仓库里。

**证据（实测）** 启动实例时**故意不设** `SKILLFEED_SESSION_SECRET`，脚本用默认密钥自行签一个 cookie，全程未走任何登录流程：

```
[forged posts/me]  GET  /api/posts/me      -> 200 {"posts":[{"id":4,"author_id":1,...}]}
[forged me]        GET  /auth/me           -> 200 {"user":{"id":1,"login":"mallory",...}}
[forged create]    POST /api/posts         -> 200 {"ok":true,"post":{"id":5,"author_id":1,...}}
[forged react]     POST /api/posts/1/react -> 200 {"ok":true}
[wrong-sig …]      GET  /api/posts/me      -> 401  （签名校验本身是对的）
```

**攻击场景** 攻击者读仓库拿到常量 → 本地脚本签发 `uid=1..N` 的 cookie → 以任意用户身份发帖、点赞、读其私有帖列表。不需要 XSS、不需要网络位置、不需要受害者交互。**这不是 IDOR，是完全的身份伪造，权限模型整体失效。**

**建议方向** 密钥缺失/等于默认值时进程应拒绝启动（fail-closed）；把密钥长度与熵作为启动自检项；上线前轮换一次密钥（等价于强制全员重登）。

---

### SEC-02 · P0 · OAuth 未配置时 fail-open 成「任何人一键登录」

**证据（代码）** `server/app.py:82-85`

```python
if not settings.oauth_configured:
    if settings.dev_auth:
        return RedirectResponse("/auth/dev-login", status_code=302)
```

`server/app.py:115-129` 的 `/auth/dev-login` **不校验任何凭据**，直接 `upsert_user(github_id=1, login=<query 参数>)` 并签发 30 天会话。

**证据（实测）**

```
GET /auth/github            -> 302 Location: /auth/dev-login
GET /auth/dev-login?login=alice    -> 302 + Set-Cookie（已登录）
GET /auth/me                -> {"user":{"id":1,"login":"alice",...}}
GET /auth/dev-login?login=mallory  -> 302
GET /auth/me                -> {"user":{"id":1,"login":"mallory",...}}   ← 同一行被改名
```

**攻击场景** 两层风险叠加：
1. 微信登录改造期间若 GitHub OAuth 环境变量临时缺失 / 部署时漏配，站点不会报错，而是静默降级成「点登录就登进去」。**配置错误 = 全站开放注册发帖。**
2. `github_id=1` 是硬编码常量，所有 dev 登录复用同一行 `users`，`login` 字段被最后一次调用覆盖 —— 一个只读接口（GET）就能改数据库里的用户名，属于 CSRF-able 的写操作。

**建议方向** dev 登录应通过构建期开关或独立入口文件隔离，不进生产制品；OAuth 未配置时任何登录入口都应 fail-closed（503），而不是找替代路径。

---

### SEC-03 · P0 · 全部写接口无速率限制、无验证码、无配额

**证据（实测）**

```
120 次连续 POST /api/posts/{id}/react   耗时 5.03s  -> Counter({'200': 120})
 40 次连续 POST /api/posts              耗时 0.72s  -> Counter({'200': 40})
 48 并发 POST /api/posts                          -> Counter({'200': 48})
 60 并发 react 反复 on/off 切换                    -> Counter({'200': 60})
```

代码中不存在任何限流中间件、令牌桶、IP 计数或 nonce。

**攻击场景** 单机脚本 55 帖/秒灌满 SQLite；`reactions` 是 `INSERT OR IGNORE`（`db.py:193-200`），单账号对单帖只能记一次，但配合 SEC-01 伪造 N 个 `uid` 即可无上限刷任意帖的点赞数——一旦排序引擎把 `reactions` 纳入权重，**榜单直接可被脚本操纵**。

**建议方向** 至少三层：入口层按 IP/设备的全局桶、应用层按用户的写配额（发帖/日）、业务层对新账号设冷却期。写接口需要能在不发版的前提下临时关停。

---

### SEC-04 · P0 · UGC 即发即上线，无审核 / 无删除 / 无举报 / 无下架能力

**证据（代码）** `server/db.py:34` `status TEXT NOT NULL DEFAULT 'published'`；`server/db.py:120-147` `create_post` 里 `data.get("status") or "published"`，而 `ugc.prepare_post_payload` 从不产出 `status`，因此**所有帖子一律直接 published**。全表 13 条路由中没有 DELETE、没有 PATCH、没有举报端点、没有管理端点。

**攻击场景** 这不是纯技术风险，是**中国大陆公网上线的合规硬门槛**：面向中国用户提供 UGC 信息服务，《网络信息内容生态治理规定》《互联网用户公众账号信息服务管理规定》要求具备内容审核、违规内容处置、用户举报受理能力；当前 API 连「把一条帖子下架」的手段都没有，出问题只能改数据库。此外站点做的是算法推荐（排序引擎），《互联网信息服务算法推荐管理规定》要求算法备案与提供关闭推荐的选项。

**建议方向** 先补最小闭环：作者删除 + 运营下架（软删除 + 审核态） + 举报入口 + 处置留痕；发布路径改为「先入待审态」或「先发后审 + 敏感词前置拦截」；把算法备案与隐私政策纳入上线检查单。

---

### SEC-05 · P0（条件触发） · CORS 允许列表为空时回退到 `*` 且携带凭据

**证据（代码）** `server/app.py:45-51`

```python
allow_origins=settings.cors_origins or ["*"],
allow_credentials=True,
```

`server/config.py:32-36` 把 `SKILLFEED_CORS_ORIGINS` 按逗号切分并 `if o.strip()` 过滤，因此形如 `","`、`" , "`、`",,"` 的配置会得到空列表，触发 `or ["*"]`。

**证据（实测，8613 实例，`SKILLFEED_CORS_ORIGINS=","`）**

```
https://evil.example.com    GET ACAO='https://evil.example.com'  ACAC='true'  preflight=200
null                        GET ACAO='null'                       ACAC='true'  preflight=200
http://attacker.local:1234  GET ACAO='http://attacker.local:1234' ACAC='true'  preflight=200
```

Starlette 在 `allow_all_origins + allow_credentials` 下会**回显请求方 Origin**，等价于「任意站点可带 cookie 读写本站 API」。作为对照，默认配置（非空白名单）行为是正确的：

```
（8611 默认实例）
https://evil.example.com        GET ACAO=None   preflight=400   ← 正确拒绝
https://469910093-ui.github.io  GET ACAO=echo   preflight=200
http://127.0.0.1:8473           GET ACAO=echo   preflight=200
```

**攻击场景** 一次运维笔误（把 CORS 变量清成 `,`）就把整站变成任意源可携带凭据访问，绕过 SameSite=Lax 对 JSON 写接口的保护。另外**默认白名单里含两个 `http://127.0.0.1` 开发源**，生产环境不应保留。

**建议方向** 去掉 `or ["*"]` 兜底，空列表就应拒绝跨域；`allow_credentials=True` 与通配符在配置层做互斥校验；生产白名单只留正式域名。

---

### SEC-06 · P1 · 会话不可撤销：登出只清客户端 cookie，旧 token 30 天内继续有效

**证据（代码）** `server/auth.py:73-74` `clear_session_cookie` 只调 `resp.delete_cookie`；无服务端会话表、无 token 版本号、无 jti 黑名单。`config.py:38` `cookie_max_age = 60*60*24*30`。

**证据（实测）**

```
logout -> 200  Set-Cookie: skillfeed_session=""; Max-Age=0
同一客户端 /auth/me            -> {"user":null,...}          ← 看起来登出了
用登出前抓下的同一 token 重放：
  /auth/me       -> {"user":{"id":1,"login":"alice",...}}    ← 仍然有效
  /api/posts/me  -> 200
```

**攻击场景** 公用电脑/被盗设备上「退出登录」不产生任何安全效果；一旦某个 token 泄漏（日志、截图、浏览器扩展），无法止血，只能全局换密钥。密钥轮换又会踢掉所有人。

**建议方向** 引入服务端可撤销维度（会话表或用户级 token 版本号），把 30 天压到更短并配刷新机制；登出、改密、风控命中时能定向失效。

---

### SEC-07 · P1 · OAuth `state` 是攻击者可自洽的双提交 cookie，回调地址未做归属校验

**证据（代码）** `server/app.py:98-100`

```python
expect = request.cookies.get("skillfeed_oauth_state") or ""
if not state or state != expect:
    raise HTTPException(400, "bad oauth state")
```

`state` 只与一个 cookie 比对，既不绑定服务端签发记录，也不绑定当前会话/来源。`server/auth.py:97-104` 的 `redirect_uri` 由 `settings.public_url` 拼出（这点是对的），但回调成功后固定跳 `/publish`，没有 `next` 参数（也就没有开放重定向面，这点是好的）。

**证据（实测）** 攻击者自设 state cookie 与 state 参数使其自洽，服务端**通过了 CSRF 校验**并继续往下走（因未配 OAuth 才 500）：

```
GET /auth/callback?code=fake&state=attacker-chosen
    (Cookie: skillfeed_oauth_state=attacker-chosen)
-> 500 Internal Server Error      ← 说明 state 校验已放行，进入了 exchange_github_code
对照：GET /auth/callback?code=abc&state=xyz（无 cookie） -> 400 bad oauth state
```

**攻击场景** 登录型 CSRF：攻击者用自己的 GitHub 账号取得 `code`，构造一个能同时设置 `skillfeed_oauth_state` cookie 和跳转 callback 的页面，让受害者在不知情下登入**攻击者的账号**，此后受害者的发帖行为落到攻击者账号下。cookie 属性是 `SameSite=lax` + `Path=/`，未加 `__Host-` 前缀，同站任意子域/中间人可写入。

**建议方向** `state` 应由服务端签发并与浏览器上下文绑定（签名 + 时效 + 一次性消费），校验后立即失效；state cookie 加 `__Host-` 前缀收紧写入面；`exchange_github_code` 的异常要转成 4xx 而不是 500。

---

### SEC-08 · P1 · UGC 内容零净化，原样存原样出，形成存储型 XSS 的待爆点

**证据（实测）** 提交含脚本的标题/描述，服务端接受并入库，`GET /api/feed` 原样返回：

```
POST /api/posts {"title":"<img src=x onerror=alert(1)>", "description":"<script>alert('xss-desc')</script> …"}
-> 200  stored title_len=28  desc_len=45
GET /api/feed?source=ugc  -> items[].name / description 中 payload 完整保留
```

`server/ugc.py:27-90` 只做长度与 GitHub URL 格式校验，无 HTML 转义、无标签白名单、无 Markdown 净化。`title` 会被 `scene.apply_scene` / `highlights` 读取后写进多个衍生字段（`name`/`one_liner`/`problem`/`body_preview`），一次注入多处扩散。

**当前缓解** 已知的两个渲染端都做了转义：`server/templates/publish.html:134-136` 的 `escapeHtml`，以及 `feed_dashboard.py` 生成的看板对每个插值都套了 `escapeHtml`（第 1174–1758 行大量出现）。所以**今天还打不穿**，因此定 P1 而非 P0。

**攻击场景** 风险在于「防线全在前端」：新增的微信 webview 页、小程序 web-view、第三方 embed、运营后台、把 `description` 塞进邮件/推送模板——任何一处用了 `innerHTML` 或不转义的模板引擎，就是全站存储型 XSS。而 SEC-01 的会话是 HttpOnly（这点是对的），但 XSS 仍可代发帖、代点赞、读 `/api/posts/me`。

**建议方向** 在写入侧统一净化（服务端负责，不依赖渲染端）；明确 `body_md` 的渲染契约（谁负责把 Markdown 转 HTML、用什么白名单）；给 API 响应加 `X-Content-Type-Options: nosniff` 与 CSP。

---

### SEC-09 · P1 · 无任何安全响应头

**证据（实测）** `/`、`/publish`、`/api/feed` 的完整响应头只有：

```
date / server: uvicorn / content-length / content-type
```

缺 `Strict-Transport-Security`、`X-Content-Type-Options`、`X-Frame-Options` 或 CSP `frame-ancestors`、`Referrer-Policy`、`Cache-Control`。`Server: uvicorn` 直接暴露技术栈。

**攻击场景** `/publish` 无 `frame-ancestors` → 可被 iframe 套壳做点击劫持（发布/退出按钮）；已登录响应（`/api/posts/me`）无 `Cache-Control: no-store` → 可能被中间代理或浏览器缓存；HTTP→HTTPS 无 HSTS → 首次访问可被降级劫持（对中国公网尤其现实）。

**建议方向** 在网关或中间件统一下发安全头；`Referrer-Policy` 要在埋点上线前定好（见 §5，`device_id` 若进 URL 会随 Referer 外泄）。

---

### SEC-10 · P2 · 交互式 API 文档与内部配置对公网开放

`/docs`、`/redoc`、`/openapi.json` 全开（实测均 200）。`/health` 返回 `{"ok":true,"oauth":false,"dev_auth":true,"official_feed":true}`——**`dev_auth` 的真值直接告诉攻击者 SEC-02 是否可利用**。`app.py:85-88` 的 503 detail 回显了 `SKILLFEED_GITHUB_CLIENT_ID/SECRET`、`SKILLFEED_DEV_AUTH` 的变量名。

**建议方向** 生产关闭文档路由或加鉴权；`/health` 只回存活状态，配置态走内网探针。

---

### SEC-11 · P2 · 无 SQL 注入面（正向确认）

`server/db.py` 全部查询均为 `?` 占位参数化，无字符串拼接；`post_id` 由 FastAPI 强制转 `int`。实测注入尝试全部被类型层挡下：

```
POST /api/posts/1 OR 1=1/react  -> 422 int_parsing
POST /api/posts/abc/react       -> 422 int_parsing
GET  /api/feed?source=evil      -> 422 string_pattern_mismatch
```

**结论：当前无注入面。** 唯一需要盯的是未来若给 feed 加 `q=` 搜索并落到 SQL/FTS，必须延续参数化。

### SEC-12 · P2 · IDOR 面很小（正向确认，附一处信息泄漏）

`/api/posts/me` 严格按 session `uid` 过滤（`db.py:176-187`）；`react` 是设计上就允许跨用户操作他人帖子的，且校验了 `status == 'published'`（`app.py:239-241`），不构成越权。`user_public()`（`db.py:208-214`）正确剔除了 `github_id`。

唯一泄漏：`POST /api/posts/{id}/react` 用 404 与 200 区分帖子是否存在且已发布，可被用来枚举 ID 空间（需登录）。当前无非公开帖，影响极低。

### SEC-13 · P2 · 出站调用未把凭据放进 URL（正向确认）

逐处核对：`skill_detect.py:134-135`、`github_search.py:37-45`、`catalog_sources.py:101-110`、`i18n.py:220-223`、`server/auth.py:126-130` 均使用 `Authorization: Bearer` 请求头。`GITHUB_TOKEN` / `DASHSCOPE_API_KEY` 未出现在 URL、日志或 API 响应中；`github_search.py` 回填的 `meta.warn` 只带 GitHub 返回的 message。**无凭据泄漏。**

---

## 3. 功能与健壮性发现

### FN-01 · P1 · `source=all` 分页语义错误，UGC 内容在第二页之后永久不可达

**证据（代码）** `server/app.py:160`

```python
posts = db.list_published_posts(conn, limit=limit, offset=offset if source == "ugc" else 0)
```

`all` 模式下 UGC 恒定只取「前 `limit` 条」，再与官方流合并后对合并结果切 `[offset: offset+limit]`。

**证据（实测，库内 93 条 UGC + 2 条官方）**

```
source=ugc&limit=2&offset=0  -> ['forged-post', 'a\x00b']
source=ugc&limit=2&offset=2  -> ['<img src=x onerror=alert(1)>', 'TTTT…']     ← 正确翻页
source=all&limit=2&offset=0  -> ['forged-post', 'a\x00b']
source=all&limit=2&offset=2  -> ['stub-one', 'stub-two']   ← 第 3 条 UGC 消失，直接跳到官方流
```

同时 `ugc_count` 返回的是**当前页**的 UGC 条数（`2`）而非总数（`93`），字段名有误导性。`me` 字段恒为 `null`（`app.py:189`），是废字段。

**故障场景** `all` 是默认 `source`。用户往下滑第二屏时，第 3 条之后的所有 UGC 帖永远不会出现——**用户发的帖除了自己在 `/api/posts/me` 里能看到，别人翻不到**。排序引擎重写时若沿用这个合并逻辑，会把 bug 固化进新分页协议。

**建议方向** UGC 与官方流的合并需要统一的游标语义（建议 cursor 而非 offset，避免新帖插入导致漂移）；`ugc_count`/`official_count` 要么改成总数要么改名。

---

### FN-02 · P1 · `/api/feed` 每次请求同步回源官方 feed，无缓存、无熔断、无并发保护

**证据（代码）** `server/ugc.py:126-139`，每次调用新建 `httpx.AsyncClient(timeout=20)` 拉一次远端；`app.py:164-165` 在请求链路里 `await` 它；无缓存层、无 ETag、无退避。

**证据（实测 A：放大比 1:1）** 官方 feed 指向本地计数桩：

```
5 × GET /api/feed?source=all  ->  上游命中数 0 → 5（delta=5），耗时 1.72s
```

**证据（实测 B：上游变慢直接传导到本站）** 把桩改成固定 sleep 3s：

```
单请求 source=all  ->  5.83s / 4.67s / 4.09s
单请求 source=ugc  ->  0.35s          （不走上游，不受影响）
20 并发 source=all ->  wall 11.60s, min 8.57s, p50 11.01s, max 11.59s
```

**故障场景** 两个方向都危险：
1. **对外**：本站每一次 feed 请求都变成一次对 GitHub Pages 的请求。站点上量后等于用自己的用户去打 Pages，触发限流后 `except Exception: return []` 静默吞掉，用户看到的是「发现流突然空了」，且日志里什么都没有。
2. **对内**：上游一慢，本站 P50 直接跟着涨到 10s+，20s 超时期间连接与 worker 全被占住。这是典型的单点拖垮。

**建议方向** 官方流必须进本地缓存（TTL + stale-while-revalidate，上游挂了返回旧数据而不是空数组）；加熔断与短超时；回源改成后台定时刷新而非请求内联；失败要有可观测的计数而不是静默 `return []`。

---

### FN-03 · P1 · `title` 无长度上限，200KB 单条内容入库并被完整回吐进 feed

**证据（代码）** `server/ugc.py:34-40` 只对 `body_md` 做了 20000 上限，`description` 在 `ugc.py:67` 被 `[:400]` 截断，**`title` 全程无截断**，`db.create_post` 原样写入。

**证据（实测）**

```
POST /api/posts {"title": "T"*200000, ...}  -> 200，stored title_len=200000
随后 GET /api/feed?source=ugc  ->  content-length: 203520
```

**故障场景** 单条 200KB × 灌帖脚本（SEC-03 已证明无限流）→ SQLite 迅速膨胀；更糟的是这些内容会进 feed 响应体、进排序引擎的索引、进 LLM 双语改写的输入（按 token 计费）。

**建议方向** 所有用户可控字符串字段统一定义最大长度并在模型层（Pydantic）声明，而不是分散在业务函数里；同时在网关层设请求体上限（当前 8MB body 会被完整读入并 JSON 解析后才在业务层报 400——实测确认）。

---

### FN-04 · P1 · SQLite 并发模型未针对多用户配置

**证据（代码）** `server/db.py:59-64`：每请求 `sqlite3.connect(check_same_thread=False)`，**未开 WAL、未设 `busy_timeout`、未设连接池**；每个请求开新连接、`commit`、`close`。

**证据（实测）** 当前负载下未复现锁冲突（48 并发发帖 48×200，60 并发 react 60×200），说明本机 SSD + 低数据量还扛得住。

**故障场景** 这是「现在没炸不代表能上线」：默认 journal 模式下写会阻塞读，`busy_timeout` 为 0 意味着一旦冲突立刻抛 `database is locked` → 500。**排序引擎即将加入的高频曝光埋点写入会和 posts 读路径抢同一个文件锁**（见 §5-R11），这是当前架构下最可能的首发生产事故。

**建议方向** 至少开 WAL + 设 `busy_timeout`；埋点这类高频写不要和业务表同库；评估是否该在上线前迁到 Postgres。

---

### FN-05 · P2 · 三处未捕获异常直接 500

| 触发 | 异常（uvicorn 日志实录） | 位置 |
|---|---|---|
| `POST /api/posts/10000000000000000000/react` | `OverflowError: Python int too large to convert to SQLite INTEGER` | `db.get_post` |
| session `uid` 指向不存在的用户后发帖 | `sqlite3.IntegrityError: FOREIGN KEY constraint failed` | `db.create_post` |
| `/auth/callback` state 自洽但 OAuth 未配 | `httpx` 异常经 `raise_for_status()` 冒泡 | `auth.exchange_github_code` |

响应体是 Starlette 默认的 `Internal Server Error` 纯文本，**未泄漏堆栈**（这点是对的），但堆栈进了服务端日志。第二项在真实场景可由「用户在数据库里被删除后旧 cookie 仍有效」触发。

**建议方向** `post_id` 加上界约束；写路径把完整性错误映射成 4xx；出站 HTTP 异常统一转 502/503。

### FN-06 · P2 · 输入接受控制字符与空字节

`{"title": "a\x00b"}` 被接受并入库（实测 `stored title_len=3`）。SQLite 能存，但下游 JSON/日志/搜索索引/Excel 导出常在这类字符上出问题。无 Unicode 归一化、无控制字符过滤、无首尾空白折叠。

### FN-07 · P2 · 本机 `serve` 模式的 `/api/feedback` 无来源校验

`skillfeed.py:844-858`：POST 无 Origin/Referer 校验、无 CSRF token、无大小限制；GET 无鉴权即可读出最近 50 条完整反馈行。因为只绑 `127.0.0.1`，任意网页发起的跨站 POST 会被 CORS 挡住简单请求之外的部分，但 `Content-Type: text/plain` 的简单请求能穿透，可污染本机 `feedback.jsonl`（进而污染 `rank.load_feedback_affinity` 的个人画像）。单用户本机形态，影响面小。

---

## 4. 出站依赖健壮性

### OUT-01 · P1 · GitHub API 限流处理缺失，且「被限流」与「仓库没有 SKILL.md」无法区分

**证据** `skill_detect.py:126-150`：

```python
except urllib.error.HTTPError as e:
    body = e.read()...
    return e.code, body            # 403 / 429 原样返回给调用方
except (urllib.error.URLError, TimeoutError, OSError):
    return 0, ""                   # 网络错误 → 与"没找到"同形
```

调用方 `fetch_raw_skill`（`:162-174`）和 `list_dir_api`（`:177-192`）一律 `if code != 200: return None/[]`。**429、403、超时、DNS 失败全部被翻译成「这个仓库没有 skill」**，然后这个结论会进 feed、进门禁统计。无重试、无退避、不读 `Retry-After`、不读 `x-ratelimit-reset`。

`github_search.py` 稍好：`:132` 记录了 `x-ratelimit-remaining`（但只记不用），`:182-184` 遇 403 时 `break` 停止后续查询（这是对的），`:199` 固定 `sleep(0.4)`。仍无退避重试。

**故障场景** GitHub 限流窗口内跑一次 refresh → 供给静默腰斩 → 门禁（覆盖率）可能仍判 PASS，因为「查了但没有」和「没查到」在数据结构上一模一样。事后无法从产物反推当时被限流。

**建议方向** 区分「确认不存在」与「获取失败」两种结果，后者不得进入产物，且要在 meta 里可见；对 403/429/5xx 做带 jitter 的指数退避并尊重 `Retry-After`；限流命中时应让整次 refresh 显式失败而不是产出残缺 feed。

### OUT-02 · P1 · 单仓探测请求数无预算，且完全无缓存

**证据** `skill_detect.py:194-233` + `:17-23`、`:53-55`：
- `CANDIDATE_PATHS` 5 条 × `fetch_raw_skill` 内 `for ref in ("HEAD","main","master")` 3 次 = **最多 15 次 raw 请求**
- 5 个 skills 基目录各一次 `list_dir_api`（打 `api.github.com`，计入 core 5000/h）
- 每个子目录 3 次 raw；`DESCEND_CAP=12` 再下钻一层，`FIND_PATHS_CAP=24`

单个仓库轻松 50–100+ 次出站请求。`skill_detect.py` **没有任何缓存**（`github_search.py` 有 12h TTL 缓存，`skill_detect` 没有），每次 refresh 全量重打。

**建议方向** 给探测加持久化结果缓存（含否定缓存，记住「这个仓库确实没有」）；用单次 Git Trees API 替代逐路径试探；设全局请求预算并在预算耗尽时显式失败。

### OUT-03 · P2 · 百炼 LLM 调用降级正确，但缺重试与成本护栏

**证据** `i18n.py:217-237`：`urlopen(timeout=60)`（`DEFAULT_TIMEOUT=60`），异常一律 `return None`；上层 `enrich_items`（`:249-320`）在无 `api_key` 时把条目计入 `skipped` 并保留原文，缓存按 `full_name + 内容 hash` 命中就不重译。

**评价**：降级路径是对的（失败不炸、退回原文、`.env.example:14-15` 也写清了）。缺的是：
- 无重试（一次瞬时 5xx 就永久丢一条译稿，直到内容 hash 变化才会重试）
- `ThreadPoolExecutor(DEFAULT_WORKERS=4)` 是固定并发，无 QPS 限制、无 429 感知
- 无 token/费用上限；配合 FN-03 的 200KB 标题，`BODY_LIMIT=1800` 限了正文但 `description`（`:211` 取 600 字符）与 `full_name` 未限
- 60s × 4 并发，在 CI 里遇上游劣化会顶到 workflow 的 45 分钟超时

**建议方向** 加有限重试与 429 退避；给单次 refresh 设条数/费用上限；把 LLM 失败率纳入门禁指标。

### OUT-04 · P2 · CI 定时任务与缓存

`.github/workflows/pages.yml`：每 6 小时 + push 触发，`concurrency: group=pages, cancel-in-progress: true`（防叠加，正确），`actions/cache` 缓存 `.skill-feed-data`，但 cache key 带 `github.run_id` 导致**每次都是新 key、只靠 `restore-keys` 回退**——缓存永远命中的是上一次的快照，尚可，但会持续堆积缓存条目。`refresh --force` 显式跳过 `github_search` 的 TTL 缓存（`github_search.py:222-227`），所以每 6 小时必然全量回源。

---

## 5. 上线门禁：公网开放前必须堵掉的 P0

按「不堵就不能开」排序。前 5 条是安全，后 2 条是合规，最后 1 条是可用性。

| # | 门禁项 | 对应发现 | 验收方式（建议） |
|---|---|---|---|
| **G1** | `SKILLFEED_SESSION_SECRET` 必须为强随机值，缺失或等于默认值时进程拒绝启动 | SEC-01 | 用默认密钥签发的 cookie 访问 `/api/posts/me` 必须 401；不设该变量启动必须失败 |
| **G2** | 生产制品中不存在 `/auth/dev-login`；OAuth 未配置时所有登录入口 fail-closed | SEC-02 | 生产环境 `GET /auth/dev-login` 必须 404；`/auth/github` 不得 302 到任何本地登录路径；`/health` 不再回显 `dev_auth` |
| **G3** | 所有写接口（发帖 / react / 未来的 events）具备限流与配额，且可在不发版的情况下关停 | SEC-03 | 单 IP 连续 100 次 react 必须出现 429；单账号发帖有日配额 |
| **G4** | 具备内容下架能力：作者删除 + 运营下架 + 举报受理 + 处置留痕 | SEC-04 | 能在 API 层把一条已发布帖子变为不可见，且有操作记录 |
| **G5** | CORS 白名单不含 `*`、不含 `127.0.0.1`，空列表不得回退到通配 | SEC-05 | 以 `Origin: https://evil.example.com` 请求，`Access-Control-Allow-Origin` 必须缺失；把 CORS 变量设成 `,` 时进程应报错而非放行全部 |
| **G6** | 备案与告知齐备：ICP 备案生效、隐私政策 / 用户协议上线、算法推荐备案启动 | SEC-04 + §5 隐私项 | 上线检查单人工确认 |
| **G7** | 匿名标识与行为数据的合规基线（PIPL）：同意后才写设备 ID、提供关闭个性化推荐、提供删除画像入口、明确留存期限 | §6-R12/R13 | 未同意状态下不产生 `device_id`、不落任何行为事件 |
| **G8** | `/api/feed` 不再在请求链路里同步回源官方 feed；上游不可用时返回缓存而非空数组 | FN-02 | 上游注入 3s 延迟后，`/api/feed` P95 不受影响；上游 100% 失败时 feed 仍有内容 |

**上线后第一批补齐（P1，不阻塞开服但要有排期）**：SEC-06 会话撤销、SEC-07 OAuth state 服务端签发、SEC-08 写入侧内容净化、SEC-09 安全响应头、FN-01 分页语义、FN-03 字段长度上限、FN-04 SQLite WAL/busy_timeout、OUT-01 GitHub 限流区分。

---

## 6. 微信登录接入的 API 影响

### 当前 schema 的迁移障碍

`server/db.py:14` `github_id INTEGER NOT NULL UNIQUE`，配合 `db.py:89-112` 的 `upsert_user`（唯一的用户写入路径，签名里 `github_id` 是必填 keyword）与 `app.py:103-109`、`app.py:120-126` 两个调用点。

| 障碍 | 说明 |
|---|---|
| **NOT NULL 挡死微信用户** | 微信登录用户没有 GitHub ID。要么塞假值（污染唯一键、后续无法区分真假）、要么改列约束。SQLite **不支持 `ALTER TABLE … ALTER COLUMN`**，去掉 NOT NULL 只能走「建新表 → 拷数据 → 改名」的重建流程，期间需停写 |
| **登录方式与用户表耦合** | 身份标识直接长在 `users` 上，每加一种登录方式就要加一列（`wx_openid`/`wx_unionid`/`phone`）并加一个部分唯一索引。三种方式并存后，`users` 上会有 3 个可空唯一列，「同一个人」的判定逻辑散落在各处 |
| **`upsert_user` 是单键 upsert** | 只按 `github_id` 查找。多身份后需要「先按 identity 查 → 找不到再建 user」的两段逻辑，现有函数签名无法承载 |
| **`login` 被当作展示名又被当作准标识** | `auth.sign_session` 把 `login` 塞进 cookie 载荷（`auth.py:57-61`）。微信昵称可含 emoji、可重复、可随时改，不能当标识用；且 SEC-02 已证明 `login` 可被 `/auth/dev-login` 任意覆写 |
| **`github_id` 硬编码 1** | `app.py:122` 的 dev 用户占了 `github_id=1`。GitHub 上真实存在 id=1 的用户，迁移时这行脏数据会和真实账号撞唯一键 |

**建议方向** 把身份从用户表拆出去：`users` 只留 profile 与内部 id，新增 `identities(provider, provider_uid, user_id)` 并对 `(provider, provider_uid)` 建唯一索引。这样加登录方式是插行而不是改表，`upsert_user` 变成 `resolve_identity → get_or_create_user`。

### 多登录方式并存的唯一性与账号合并风险

| 风险 | 说明 |
|---|---|
| **UnionID vs OpenID 选错 = 账号裂开** | OpenID 是「用户 × 单个应用」维度，UnionID 才是「用户 × 开放平台主体」维度。若按 OpenID 建账号，将来加了小程序或另一个公众号，同一个人会得到两个账号。**必须以 UnionID 为主键身份，OpenID 只作辅助记录**——但 UnionID 需要开放平台绑定，公众号登录尚未完成时就要把这件事定下来 |
| **手机号是最危险的合并键** | 手机号会被运营商回收再放号。用手机号自动合并账号，等于「新机主自动继承前机主的账号」。手机号只能作为验证过的辅助属性，不能作为自动合并的唯一依据 |
| **合并方向不可逆** | 一旦把两个 user_id 合并（帖子、reactions 迁移），拆不回来。`reactions` 主键是 `(user_id, post_id, kind)`，合并时会撞主键，需要显式的冲突策略 |
| **抢注 / 账号劫持** | 若允许「已登录状态下绑定新身份」，绑定接口必须校验当前会话与目标身份都未被占用，且要防 CSRF——当前 `/auth/callback` 的 state 校验（SEC-07）扛不住这个场景 |
| **`reactions.user_id` 无 ON DELETE/UPDATE 策略** | `db.py:49-50` 只声明了 FK，没有级联行为。合并/注销用户时需要手工处理孤儿行 |
| **注销权（PIPL）** | 面向中国用户必须提供账号注销。当前无删除路径，且帖子与用户强 FK 关联（`db.py:37`），注销时是删帖、匿名化还是转移，需要先在数据模型层定义 |

**建议方向** 先定「身份 = UnionID」这一条主线，其余（GitHub、手机号）都作为可绑定的次级身份；合并只允许用户显式发起且需双向验证；在改 schema 之前把注销/合并的数据处理规则写进设计文档，否则迁移做完还得再迁一次。

---

## 7. 曝光埋点接口的设计要求（给排序引擎 agent）

已读 `docs/frontend-event-contract.md`（状态：待评审）。契约本身相当完整——`impression` 的 50%/300ms 门槛、`dwell` 的可见时长累计与 visibilitychange 暂停、阈值判定放服务端、`sendBeacon`、离线环形缓冲、`not_interested` 的 scope 由用户自选，这些都写得很扎实。**以下是从 API 安全与健壮性角度补充的要求，不是重新设计。**

### 7.1 防刷与身份（最关键，当前契约完全没覆盖）

| # | 要求 | 理由 |
|---|---|---|
| **R1** | `/api/events` 匿名可写 + 排序直接吃这些数据 = **榜单可被脚本操纵**。必须有防刷预算：按 IP、按 `device_id`、按 `(device_id, 时间窗)` 三层限额，超限静默丢弃（返回 200 但不计入） | 契约 §3「无需登录，匿名可写」+ 无任何限额。SEC-03 已证明现有写接口零限流。攻击者 curl 循环即可把任意 `item_key` 顶上首页 |
| **R2** | `device_id` / `session_id` 是客户端 `crypto.randomUUID()` 自铸的，**攻击者可无限量铸造身份**。服务端不能把它们当可信身份，必须有「新设备的信号权重打折 / 需要行为多样性才计入」之类的抗女巫设计 | 契约 §1。去重只防重复，不防伪造 |
| **R3** | 去重键 `device_id+session_id+item_key+action+client_ts` 里 `client_ts` 由客户端给 —— 攻击者每次换一个 ts 即可绕过。**改用客户端生成的 `batch_id`（每次 flush 一个 UUID）做幂等键**，重试复用同一 `batch_id`，比「重试必须复用原始 client_ts」更不容易被前端实现错，也更省服务端索引 | 契约 §2 + §3「失败降级」 |
| **R4** | `client_ts` 必须与服务端时间做偏移校验：超出 ±N 分钟的一律拒绝或钳制到服务端时间；同时**服务端必须自己记 `server_ts`**，所有时间窗口计算用服务端时间 | 客户端时钟可被随意设置，倒填时间可污染时间衰减权重 |
| **R5** | 写接口需要一个**不发版就能关停**的开关（feature flag / 配置热加载），并且关停后 feed 必须照常工作 | 上线首日被刷时唯一的止血手段 |

### 7.2 请求协议与体积

| # | 要求 |
|---|---|
| **R6** | 除「单请求 ≤200 条」外，必须再加**字节上限**（建议 ≤64KB）。当前每个事件有 `item_key`/`owner`/`scene`/`scene_l2`/`source` 五个客户端可控字符串，200 × 无限长 = 无界 payload。参考 FN-03：`title` 就是因为「只限条数不限长度」被灌进 200KB |
| **R7** | `item_key` 必须做严格校验：字符集白名单 + 长度上限 + 最好校验是否为已知条目。否则攻击者可写入任意高基数字符串，撑爆排序侧的统计表 / 内存 map，同时构成日志注入面 |
| **R8** | 未知 `action`、未知字段一律丢弃而非报错；**单条事件非法不得使整批失败**。响应应返回 `{accepted, deduped, rejected}` 三个计数，让客户端能观测但不必处理 |
| **R9** | 端点必须**绝不返回 5xx**（校验失败也返回 200 + 计数）。契约 §3 说「响应永远不影响页面渲染」，但客户端 §3 又定义了「连续失败 10 次停止上报」——如果服务端因一条脏数据 500，会触发客户端全量退避，等于自伤 |
| **R10** | **`sendBeacon` 与 `Content-Type: application/json` 有冲突**：beacon 默认发 `text/plain`，要发 JSON 必须传 `Blob({type:'application/json'})`，而这会触发 CORS 预检——**页面卸载期间预检无法完成，跨域 beacon 会静默丢失**。同源（skillfeeder.cn）没问题，但 GitHub Pages 上的 embed 是跨域的，那里的 beacon 会全丢。要么服务端同时接受 `text/plain` body，要么明确 embed 不上报 |

### 7.3 存储与容量

| # | 要求 |
|---|---|
| **R11** | **不要把事件写进 `server.db`**。`server/db.py:59-64` 每请求新建连接、未开 WAL、`busy_timeout=0`，默认 journal 模式下写会阻塞读。曝光量级比发帖高 3–4 个数量级，直接会把 `/api/feed` 和 `/api/posts/*` 一起锁死（FN-04）。事件走独立存储 / 独立文件 / append-only 日志，或至少独立 DB 文件 + WAL |
| **R12** | 服务端按 `(device_id, session_id, filter_signature)` 缓存排序结果（契约 §1）——**这个 key 完全由攻击者铸造，是无界内存增长**。必须是带上限的 LRU + TTL，并有缓存条目数指标 |
| **R13** | 事件必须定义留存期限与聚合降采样策略（原始事件保留 N 天 → 聚合成画像 → 原始数据删除），否则既是成本问题也是合规问题 |

### 7.4 隐私合规（面向中国用户，PIPL）

| # | 要求 |
|---|---|
| **R14** | `device_id` 是**设备唯一标识符，属于个人信息**。《个人信息保护法》要求告知并取得同意后才能收集。**契约里 `device_id` 在「首次访问」就生成——必须改成「取得同意后才生成」**，未同意状态下不铸 ID、不上报事件、feed 退化为全局排序（契约 §6 已经支持这种降级，正好复用） |
| **R15** | 《互联网信息服务算法推荐管理规定》第十七条：必须提供**关闭算法推荐服务的选项**、提供不针对个人特征的选项、以及**删除定向标签的功能**。API 层需要对应的三个能力：关闭个性化（等价于 `ranking_mode: global`）、停止事件收集、删除本设备画像（一个删除端点，凭 `device_id` 即可调用） |
| **R16** | **`device_id` / `session_id` 不要放 query param**（契约 §6 目前是 `GET /api/feed?device_id=…`）。URL 会进 CDN 日志、Nginx access log、Referer 头、浏览器历史，个人标识符从此散布到无法治理的地方。改走请求头或 POST body；若必须用 GET，配合 `Referrer-Policy: same-origin`（SEC-09 目前一个安全头都没有） |
| **R17** | 服务端隐式收集的 IP 也是个人信息。需要明确：是否入库、留存多久、是否做截断。同时《网络安全法》要求网络日志留存不少于 6 个月——**留存下限（合规要求）与最小化（PIPL 要求）需要一起设计**，不能只做一头 |
| **R18** | 登录用户的 `user_id` 与匿名 `device_id` 一旦关联，匿名数据就变成可识别的个人信息，适用范围更严。要明确「是否关联、何时关联、用户注销时如何断开」，并在隐私政策里写清 |

### 7.5 与现有接口的兼容性提醒

- 契约 §6 给 `/api/feed` 新增 `device_id`/`session_id`/`q`/`scene`/`scene_l2` 参数。当前 `/api/feed` 对未知 query 是**忽略**而非报错（FastAPI 默认行为），所以老客户端不会挂，但新参数缺失时的降级路径要显式测试。
- 契约 §6 响应新增 `session_id`/`ranking_mode`/`rank_slot`/`rank_debug`。注意 `rank_debug` 只在 `?debug=1` 返回——**`debug=1` 必须不能被普通用户利用来反推排序权重**（刷榜者会拿它当反馈信号做优化）。建议 debug 需要额外凭据。
- FN-01 的分页 bug 必须在新排序引擎里一并修掉，否则 `offset` 语义在「会话缓存切片」模型下会更混乱。
- `/api/events` 是匿名端点，**不应读取也不应要求会话 cookie**。结合 SEC-05，该端点的 CORS 策略应独立配置为 `allow_credentials=False`。

---

## 附录 · 探测环境与清理

```
实例 A: uvicorn server.app:app 127.0.0.1:8611
        SKILLFEED_DB=%TEMP%\skillfeed-apireview\probe.db
        SKILLFEED_HOME=%TEMP%\skillfeed-apireview
        SKILLFEED_DEV_AUTH=1
        SKILLFEED_OFFICIAL_FEED_URL=http://127.0.0.1:8612/feed.json   (本地计数桩)
        SKILLFEED_PUBLIC_URL=http://127.0.0.1:8611
        SKILLFEED_SESSION_SECRET / SKILLFEED_CORS_ORIGINS 未设置（用于验证默认值行为）

实例 B: uvicorn server.app:app 127.0.0.1:8613
        SKILLFEED_PUBLIC_URL=https://skillfeeder.cn   (验证 Secure cookie)
        SKILLFEED_CORS_ORIGINS=","                    (验证 CORS 空列表回退)

依赖版本: Python 3.14.4 / fastapi 0.140.7 / httpx 0.28.1
```

**未对 skillfeeder.cn、`469910093-ui.github.io`、api.github.com、dashscope.aliyuncs.com 发起任何请求。**
探测脚本（`scripts/_tmp_probe_api.py`、`_tmp_probe_cors.py`、`_tmp_probe_slow.py`、`_tmp_stub_upstream.py`、`_tmp_stub_slow.py`）与临时 DB 已删除。仓库代码零改动，未 commit。

---

## 附录 B · 评审期间 `server/` 已被并行修改（17:05 快照）

写完本文后再看工作区，排序引擎 agent 已经把改动落进 `server/`：`app.py +155 / config.py +23 / db.py +263`，新增 `server/ranking_service.py`、`server/ratelimit.py`、`impressions.py`、`ranking.py`、`ranking_profile.py`。**§1–§4 的全部结论基于 16:46 的快照，未在新代码上重跑探测**（对方仍在改，此时探测既不公平也不稳定）。以下仅为静态速读，供交叉核对。

### 已经被新代码覆盖的要求

| 我的要求 | 新代码 | 评价 |
|---|---|---|
| R1 埋点限流 | `server/ratelimit.py` `EventLimiter`，IP + device 双滑动窗口，默认 600/设备 400 每 300s | 到位。**超限静默丢弃而非 429** 的取舍与理由写在模块 docstring 里，判断正确 |
| R5 可关停 | 阈值走 `ranking_config`，可配置 | 部分到位（能调阈值，但没看到全局开关） |
| R6 条数上限 | `MAX_EVENTS_PER_REQUEST = 200`，`device_id`/`session_id` 截断到 64 字符 | 条数与 ID 长度已限，**字节上限仍缺** |
| R12 排序缓存有界 | `SessionOrderCache(ttl_s, max_entries=5000)`，`SlidingWindow(max_keys=20000)` + 驱逐 | 到位，两处都有上限与淘汰 |
| FN-01 分页 | `/api/feed` 改为一次取 200 条后统一排序再切片，新增 `total` 字段 | 分页语义修正了，但引入新上限（见下） |

### 新代码里我会继续追的点

| 严重度 | 发现 |
|---|---|
| **P1** | `_client_ip()` 无条件信任 `X-Forwarded-For` 首段。攻击者每个请求换一个伪造 IP 即可绕开 IP 限流；device 维度又是客户端自铸 UUID，同样可无限换。**结果是 R1 的限流在直连或未清洗该头的网关后面整体可被一行 header 绕过。** 只有在可信反向代理会覆写该头时才成立，需要显式确认部署形态 |
| **P1** | `/api/events` 仍写 `settings.db_path`（与 posts 同一个 SQLite 文件）。R11 未落地，FN-04 的锁竞争风险仍在，而且现在是高频写 |
| **P1** | `POST /api/profile/claim` 只校验「调用方已登录」，不校验「这个 `device_id` 真的属于调用方」。知道/猜到他人 `device_id` 即可把他人匿名画像并到自己账号，或反向把污染画像塞给目标账号。需要设备侧持有可验证凭据（如首次上报时服务端下发的设备令牌） |
| **P1** | `device_id` / `session_id` 仍走 GET query param（R16）。个人标识符会进 access log / Referer / CDN 日志，且当前一个安全响应头都没有（SEC-09） |
| **P2** | `db.list_published_posts(conn, limit=200, offset=0)` 硬上限 200。UGC 超过 200 条后，第 201 条起永远进不了排序候选集 |
| **P2** | 埋点 payload 只限条数不限字节；单事件内字符串字段（`item_key` / `owner` / `scene`）长度未见校验（R7） |
| **P2** | 未见同意门禁与「关闭个性化 / 删除画像」端点（R14 / R15），G7 门禁未满足 |

上述均**未做任何修改**，请排序 agent 自行判断取舍。
