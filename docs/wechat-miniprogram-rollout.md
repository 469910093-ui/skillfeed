# 微信：公众号就绪 → 接到小程序

公开试用页先走 GitHub Pages 信息流（无登录、无发布）。
后端和小程序按下面顺序，**不要跳步**。AppSecret 只放服务器环境变量，不要发到聊天里。

## 先分清三套身份

| 东西 | 是什么 | 现在用来干什么 |
|------|--------|----------------|
| 公众号（服务号 / 订阅号） | 你说已经 ready 的那个 | 服务号才能做 **网页授权登录 H5**。订阅号不行。 |
| 小程序 | **另一套 AppID**，要单独注册 | 微信里的壳。最快路径是壳里用 `<web-view>` 打开已备案 H5。 |
| 备案域名 + 国内 HTTPS | 主体、ICP、证书 | 网页授权域名、小程序业务域名、用户从微信里打开，都要它。 |

公众号 ready ≠ 小程序 ready。没有小程序 AppID 时，先把 **H5 主站** 跑通，再包进 web-view。

## 第 1 步（你来，现在就做）

回我这五条，缺一条就配不下去：

1. 公众号是 **服务号** 还是 **订阅号**？有没有完成微信认证？
2. 已备案的主站域名是什么？（只要主机名，例如 `skillfeeder.cn`，不要带 `https://`）
3. 域名现在指到哪？国内轻量服务器 / 还没解析 / 仍指 GitHub Pages？
4. 有没有已经注册的 **小程序**？有的话只回「有，AppID 已申请」——**不要把 AppSecret 发过来**。
5. 服务器系统：Linux？能不能 SSH？要不要我按「一台 Ubuntu + Caddy + systemd」写命令？

同时请你在本机（不要提交 git）建好 `.env`，至少：

```
SKILLFEED_SESSION_SECRET=   # python -c "import secrets;print(secrets.token_urlsafe(32))"
SKILLFEED_PUBLIC_URL=https://你的备案域名
SKILLFEED_WECHAT_APP_ID=    # 服务号 AppID
SKILLFEED_WECHAT_APP_SECRET=# 只放服务器，不要贴到对话
SKILLFEED_REQUIRE_LOGIN=0   # 试用期信息流先开门；登录接上后再改回 1
```

## 第 2 步（我来，等你回第 1 步）

- 服务号后台填网页授权域名 = 第 1 步的主机名
- 服务器装 Python、Caddy（HTTPS）、systemd 跑 `uvicorn server.app:app`
- 回调地址：`https://你的域名/auth/wechat/callback`
- 用微信内打开 `/login` 走通一次授权

## 第 3 步（小程序壳）

1. 微信公众平台注册小程序（企业主体，和备案主体一致最快）
2. 小程序后台 → 开发 → 开发管理 → 开发设置 → **业务域名** 填同一备案域名
3. 一个页面：`<web-view src="https://你的域名/"></web-view>`
4. 用微信开发者工具预览，再提交审核

web-view 要求：已认证小程序 + 业务域名已备案 HTTPS。个人主体小程序往往开不了 web-view。

## 现在先不做什么

- 不把整站重写成 WXML（那是另一条产品线）
- 不在公开 Pages 上开发布、不开强制登录
- 不把 AppSecret 写进仓库或前端
