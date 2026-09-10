# 微信：公众号就绪 → 接到小程序

公开试用页先走 GitHub Pages 信息流（无登录、无发布）。
后端和小程序按下面顺序，**不要跳步**。AppSecret 只放服务器环境变量，不要发到聊天里。

## 已锁定（2026-09-10）

| 项 | 现状 |
|----|------|
| 公众号 | **服务号，已认证** |
| 域名 | `skillfeeder.cn`，解析已加 |
| 服务器 | 阿里云轻量 · 华东 2（上海）· Ubuntu · 当时实例名 `Ubuntu-aetx` |
| 小程序 | 下一步：用已认证服务号**复用资质**注册，不要走个人主体 |
| 试用期登录 | `SKILLFEED_REQUIRE_LOGIN=0`，信息流先开门 |

## 第 2 步（今天你做）：服务号网页授权域名

打开 https://mp.weixin.qq.com/ → 已认证的那个服务号。

1. **设置与开发 → 公众号设置 → 功能设置 → 网页授权域名**
2. 填：`skillfeeder.cn`  
   不要带 `https://`，不要带 `/`，不要填 `www.skillfeeder.cn`（要 www 就再加一条，先把裸域配上）
3. 按页面提示下载校验文件。等服务器 Nginx/Caddy 起来后，把这个文件放到网站根目录，微信才能点「确认」。
4. **开发 → 基本配置**：记下 AppID；开发者密码（AppSecret）只复制到服务器 `.env`，不要发到对话、不要进 git。

回调地址（不用填进微信后台，是我们服务端拼的）：

`https://skillfeeder.cn/auth/wechat/callback`

## 第 2 步（同时）：确认主站现在是什么

在**手机流量**或家里网络打开（公司网可能被拦）：

- https://skillfeeder.cn/
- https://skillfeeder.cn/health

把结果回我一句即可，例如：「首页是信息流 / 空白 / 证书报错 / 打不开 / health 返回 ok」。

本机办公网探测过：握手超时或连接被重置；外部探测拿到过 500。所以域名大概率已经指到机器，但 **HTTPS 或应用还没稳定**，微信授权现在配了也回调不回来。

### 怎么连上服务器（不会 SSH 就走这一段）

SSH 不是装软件，是阿里云网页里弹出一个黑窗口。按这个点：

1. 打开 https://swas.console.aliyun.com/
2. 左上角地域选 **华东2（上海）**
3. 点进那台 Ubuntu 服务器（以前叫 `Ubuntu-aetx`）
4. 点卡片上的 **「远程连接」**
5. 选 **Workbench / 一键登录**（浏览器里直接开，不用下客户端）
6. 若要密码：回轻量该实例的 **「设置密码」**，设好 `root` 密码再连

黑窗口出现、末尾有 `$` 或 `#` 就成功了。把下面 **整段复制、粘贴、回车**，把屏幕上的字截图或复制发我（公网 IP 中间几位打码即可）：

```bash
hostname
ip -4 addr show | sed -n '1,20p'
ss -lntp | head -20
command -v nginx && sudo nginx -t
command -v caddy && caddy version
echo "no nginx/caddy" 
```

连上之前也可以先在控制台帮我确认两样（截图即可）：

- 实例卡片上的 **IP 地址**
- **防火墙**：必须放行 **80（HTTP）** 和 **443（HTTPS）**。只开了 22 的话，手机和微信都会 -1004
- 云解析 https://dns.console.aliyun.com/ → **试用信息流先指 GitHub Pages**（备案完成、后端起来前不要指大陆 IP，否则会被未备案拦截）：
  - 删掉 `@` 指向阿里云的 A 记录
  - 加 4 条 A：`185.199.108.153` / `109.153` / `110.153` / `111.153`
  - 微信校验文件 `MP_verify_*.txt` 已随 `publish-site` 打进静态站根目录
  - 备案完成后再把 `@` 改回轻量 IP，由 Nginx 反代 `/auth` 并继续托管校验文件

## 第 3 步（我来，等上面两段回来）

- 服务器：Caddy 或 Nginx 终结 HTTPS，反代到 `uvicorn` `:8787`
- `.env`：`SKILLFEED_PUBLIC_URL=https://skillfeeder.cn` + 服务号 AppID/Secret
- 先 `REQUIRE_LOGIN=0`，微信内打开 `/login` 走通一次授权再考虑关门
- 小程序通过后再：业务域名填 `skillfeeder.cn`，一个页面 `<web-view src="https://skillfeeder.cn/">`

## 现在先不做什么

- 不等小程序审核完再配服务号（两套 AppID，互不阻塞）
- 不把整站重写成 WXML
- 不在公开 Pages 上开强制登录或发布
- 不把 AppSecret 写进仓库或前端
