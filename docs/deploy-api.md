# 让用户能「登录账号」（接上云端）

「未接云端」不是用户坏了，是这份静态页还没挂上 FastAPI。

现在的 skillfeeder.cn 托管 `index.html` 和 Agent Surface（`/llms.txt` 等）。`/login`、`/health`、`/api/*` 必须反代到 FastAPI。
收藏 / 关注先记在浏览器里；登录、我的发布、换设备同步必须有 API。

## 用户侧看到什么

| 页面状态 | 「我的」页 |
|---|---|
| 没挂 API（现在线上） | 游客 + **登录账号** → `https://skillfeeder.cn/login` |
| API 已挂、未登录 | 游客 + 登录账号 → 本站 `/login`（微信 / 短信） |
| 已登录 | 头像、昵称、退出；三个分栏跟账号走 |

收藏、关注、我的发布三个分栏始终在。没登录时前两栏用本机数据，发布栏提示先登录。

## 服务端一次做完

在阿里云轻量上把 FastAPI 常驻到 `127.0.0.1:8787`，Nginx 把登录和 API 反代过去，静态首页仍由现在的 scp 覆盖。

1. 机器上准备代码与数据（任选一处，例如 `/opt/skill-feed`）
2. 复制 `scripts/skillfeed-api.service` 到 `/etc/systemd/system/`
3. 在同目录放 `.env`（见仓库 `.env.example`），至少要有：

```
SKILLFEED_PUBLIC_URL=https://skillfeeder.cn
SKILLFEED_REQUIRE_LOGIN=1
SKILLFEED_SESSION_SECRET=<长随机串>
SKILLFEED_GITHUB_LOGIN_VISIBLE=1
SKILLFEED_GITHUB_CLIENT_ID=...
SKILLFEED_GITHUB_CLIENT_SECRET=...
SKILLFEED_TRUSTED_PROXY_HOPS=1
SKILLFEED_TRUSTED_PROXY_IPS=127.0.0.1
SKILLFEED_SITE_DIR=/var/www/html
SKILLFEED_OPERATOR_LOGINS=<你的 GitHub login>
SKILLFEED_REVIEW_WEBHOOK=<飞书自定义机器人 webhook，可选>
```

投稿进 `pending` 后如果配了 webhook（`.env` 的 `SKILLFEED_REVIEW_WEBHOOK`，或登录运营账号打开 `/op` → 页面配置粘贴飞书自定义机器人），会给运营群推一条（含 `/op?tab=review` 链接）。没配则只落库，投稿页显示「审核中」，不会发 IM / 邮件。运营后台：`https://skillfeeder.cn/admin`（`/op` 同页；`SKILLFEED_OPERATOR_LOGINS` 白名单）。已上架卡片短链：`https://skillfeeder.cn/p/{仓库名}`。路径分析：`/op#path`。用户库每日备份：`scripts/skillfeed-db-backup.timer`（`python skillfeed.py backup-db`）。已登录用户可在「我的」绑微信/手机并导出账本；投稿仍只收 GitHub 链接。

认领仓库要求登录名等于 owner，所以 **发新帖仍要 GitHub**。日常进「我的」应再绑微信或手机。`SKILLFEED_DEV` 生产环境不要开。

手机端：微信 / 小红书 / 抖音内置浏览器完成不了 GitHub OAuth。用户必须用 Safari 或 Chrome 打开 `https://skillfeeder.cn/login`。`/auth/github` 先回 200 中转页再跳 GitHub，避免 iOS/WebView 丢掉 302 上的 state Cookie。

GitHub OAuth App 回调：`https://skillfeeder.cn/auth/github/callback`  
Homepage：`https://skillfeeder.cn`

4. 把 `scripts/nginx-skillfeeder.conf` 里的 `location` 段并进现有站点配置后 `nginx -t && systemctl reload nginx`
5. `systemctl enable --now skillfeed-api`
6. 打开 https://skillfeeder.cn/health 应返回 JSON，https://skillfeeder.cn/login 是登录页
7. GitHub 仓库 Variables 加 `SKILLFEED_PUBLIC_URL=https://skillfeeder.cn`，再跑一次 Refresh & Pages，让前端 `api_base` 写成同源

微信服务号「网页授权域名」填 `skillfeeder.cn`。回调：`https://skillfeeder.cn/auth/wechat/callback`。
