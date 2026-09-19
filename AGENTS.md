# AGENTS.md — skill-feed 安装与引导

你正在帮用户安装 **skill-feed**（与 skill-picker **拆产品线**）。

## 产品一句话

> 从 GitHub Trending + HelloGitHub + GitHub Search + 策展目录 + 小红书热议 发现 **skill 与 MCP** → 门禁 → **无限下滑 Feed** → **打开 GitHub**。  
>
> **数据分层：** 飞书资源清单是**最底层底表**（全、准确：爬到的一律进表，不论是不是 skill）。skill-feed **只基于底表按自己的门槛筛**进信息流（skill 形 + 可判定的 MCP）。底表有、Feed 没有 = 正常。详见 `docs/PRD.md` §6.0。  
>
> **硬性规定（假刷新禁止）：** 任何 refresh / ingest / bitable push / Pages 若失败、0 条成功、或内容指纹未变（NO_NEW），**必须立刻用简体中文通知用户并写明卡点**；禁止说「已刷新成功」。WaytoAGI 批次见 `docs/waytoagi-kb-batch.md` + `scripts/ingest_waytoagi.py`。  
> **不代装**。用户自行安装后用 skill-picker `scan`。

### 双变体（必知）

| 变体 | 命令产物 | 给谁用 |
|---|---|---|
| **full** | `~/.skill-feed/feed.html` · `site/index.html` | 独立网页（动态圆环/关注/发布/我的） |
| **lite** | `~/.skill-feed/feed.lite.html` · `site/embed.html` | skill-picker「去 GitHub 发现」子页（无关注/发布/后台） |

```bash
python skillfeed.py build          # 同时写 full + lite
python skillfeed.py publish-site   # 独立站：site/index.html + site/embed.html
```

## 安装 / 打开信息流

```bash
cd skill-feed
python skillfeed.py corpus     # 首次：HelloGitHub → 知识库
python skillfeed.py refresh    # 联网多源刷新
python skillfeed.py serve      # 竖滑信息流（会自动 build）
```

数据目录：`~/.skill-feed/`（`feed.json` / `feed.html` / `corpus/` / `feedback.jsonl`）。

## 常用命令

- `python skillfeed.py refresh [--since daily|weekly] [--force] [--intent TEXT]`
- `python skillfeed.py xhs-crawl [--keyword TEXT] [--max N]` — 媒讯助手/Chrome 采小红书
- `python skillfeed.py build [--intent TEXT]` — 不联网重生信息流 HTML
- `python scripts/harvest_github_2k_skills.py` — 分片搜索 GitHub ≥2000★ skill 形 → 底表 + Feed
- `python skillfeed.py i18n [--force] [--limit N] [--model NAME]` — 只补中英双语卡片文案
  （需 `DASHSCOPE_API_KEY`；缓存在 `~/.skill-feed/i18n/cards.jsonl`，页面默认显示中文）
- `python skillfeed.py bitable init --base-token TOKEN` — 在飞书 Base 里建「译稿库」表
- `python skillfeed.py bitable pull` — 表 → 本地缓存，把人工验收/改写的译稿拉回来
- `python skillfeed.py bitable push` — 新译稿 → 表（**永不覆盖已验收的行**）
- `python skillfeed.py bitable sync` — pull → 重跑 i18n → push，一条命令走完
- `python skillfeed.py bitable dedupe` — 清掉唯一键重复的行
- `python skillfeed.py corpus [--max-issues N]`
- `python skillfeed.py publish-site [--out site]` — 导出 GitHub Pages 静态站
- `python skillfeed.py api [--port 8787]` — 云端 API（登录 + UGC，需 `requirements-server.txt`）
- `python skillfeed.py serve [--port 8473]`
- `python skillfeed.py check`
- `python skillfeed.py feedback`

公开站：Actions 工作流 `Refresh & Pages` 每 6 小时 refresh 并部署到  
`https://469910093-ui.github.io/skillfeed/`（`SKILLFEED_HOME` 可覆盖数据目录）。

UGC API：`server/`（FastAPI + SQLite）。本地可先 `SKILLFEED_DEV_AUTH=1`，生产配 GitHub OAuth（见 `.env.example`）。`/auth/github` 必须先回 200 中转页再跳 GitHub，禁止对授权页直接 302（手机 WebView 会丢 state Cookie）。微信/小红书/抖音内置浏览器完成不了 GitHub 登录，须 Safari/Chrome。

## 运营后台加权限（勿误改误删）

`/op` `/admin` `/api/op/*` 只认环境变量白名单，**没有页面加点人**。

| 项 | 规定 |
|---|---|
| 变量 | `SKILLFEED_OPERATOR_LOGINS`（逗号分隔，小写比对） |
| 代码 | `server/config.py` → `auth.require_operator` |
| 生产 | `/opt/skill-feed/.env`，改完 `sudo systemctl restart skillfeed-api` |
| 当前 | `469910093-ui`。未获用户点名不得删、清空、覆盖 |

加人：对方用**自己的 GitHub** 登录 skillfeeder.cn → **追加**其 login 到现有名单 → 重启 API。微信/短信派生 login 对不上。未登录 302 `/login`；不在名单 403。

禁止：删 `require_operator`；把 `/op` `/api/op` 放进 `GATE_PUBLIC`；做加运营 UI / 自建密码；把 Client Secret / SESSION_SECRET 发给同事。

用户财产在 SQLite `users.id`，不在 GitHub。已登录可绑微信/手机到同一行（钥匙占用则拒绝）。`python skillfeed.py backup-db` 打库备份；投稿仍只收 GitHub 链接。

## PRD 同步（强制）

产品真相源：`docs/PRD.md`（含 §0 变更纪律、§13 变更日志）。

当你或用户做**任何产品调优**（IA、动态圆环/pills、关注、排序/门禁、文案引导、存储 key、里程碑取舍等）：

1. **同批更新** `docs/PRD.md` 正文对应章节  
2. **追加** §13 变更日志一行（日期 · 摘要 · 影响）  
3. 必要时刷新 §12 开发现状对照  
4. 代码与 PRD 冲突时，**先改 PRD 再改代码**（或同 PR 内两者一起改完）  

未回写 PRD 的产品改动视为未完成，不得只改 `feed_dashboard.py` / 引擎参数就结束。

## 小红书 → GitHub → 多维表格（强制 loop）

每次收到媒讯助手 / web-collection 导出的小红书 CSV 后，**必须**跑：

```bash
cd skill-feed
python scripts/xhs_bitable_loop.py run --note-link-limit 8
python scripts/xhs_bitable_loop.py audit-stars
```

流程：
1. 读**原 CSV 原地更新**（不新建 CSV）：补 `正文`，追加 `提取GitHub仓` / `校验状态` / `评星` / `是否通过门禁` / `更新时间`
2. connector 缓存 + web-collection `noteLink`（local，限量）补正文
3. GitHub 实网校验：存在则写入飞书底表（**不论是否过 skill 门禁**），来源=小红书；星数 / 有无 `SKILL.md` 记在字段里求准
4. skill-feed 再按 `min_stars`（默认 20）+ `SKILL.md` 等门槛从底表筛进 Feed

底表全量导出可用 `export_to_bitable.py --scope full`（这是底表使命）。公开 Feed 漏斗仍看 `--scope feed`，勿把两者当成同一份清单。

## 注意

- CTA 只有「打开 GitHub」；无 install / 不写宿主 skills 目录
- 动态圆环 = 关注动态；pills = 发现筛选（见 PRD §5.0）
- Trending 抓取失败时回退缓存并 WARN，不编造榜单
- 知识库只增不删；空 Feed 时用 corpus backup + 漏斗解释

## 安全规范（铁律）

| 项 | 规定 |
|---|---|
| **凭据不入库** | 一切密钥 / token / secret 只从环境变量读（见 `.env.example`），**绝不**硬编码进代码或写进 git。`SKILLFEED_SESSION_SECRET`、`SKILLFEED_GITHUB_CLIENT_SECRET`、各 `*_API_KEY`、`*_TOKEN` 都属此列 |
| **飞书 base_token 不是密钥** | 飞书多维表格的 `base_token` 出现在分享 URL 里是飞书的设计，不算密钥，可进代码 / 配置；但底表**导出产物**（manifest / ndjson / `export_to_bitable.py` 的落盘文件）含全量行数据，**不入库**（`.gitignore` 已覆盖 `_tmp_*` 与导出目录） |
| **临时脚本不入库** | 一次性探查 / 调试脚本统一用 `_tmp_` 前缀（如 `_tmp_filter_ugc.json`），`.gitignore` 已忽略；不要把 `_tmp_` 文件 commit 进去 |
| **外部调用必带 timeout** | 所有 `requests.get/post`、`httpx`、`urllib` 调用外部 API 必须显式传 `timeout=`，禁止裸调用（默认无限挂住）。飞书 / GitHub / 小红书 / 媒讯助手等外网都算 |
| **GitHub Push Protection** | 建议在仓库 Settings → Code security → Push protection 启用，拦住误推的密钥；本仓库 `.env` 已在 `.gitignore` |
| **Dependabot** | `.github/dependabot.yml` 每周扫 pip 与 github-actions 依赖，出 PR 由人审过后再合，不自动合 |
| **运营后台** | `/op` `/admin` `/api/op/*` 只认 `SKILLFEED_OPERATOR_LOGINS` 环境变量白名单，无页面加点人；不在代码里写死 login 名单 |

