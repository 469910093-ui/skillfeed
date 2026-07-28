# AGENTS.md — skill-feed 安装与引导

你正在帮用户安装 **skill-feed**（与 skill-picker **拆产品线**）。

## 产品一句话

> 从 GitHub Trending + HelloGitHub + GitHub Search 发现 skill → 门禁 → **无限下滑 Feed** → **打开 GitHub**。  
> **不代装**。用户自行安装后用 skill-picker `scan`。

### 双变体（必知）

| 变体 | 命令产物 | 给谁用 |
|---|---|---|
| **full** | `~/.skill-feed/feed.html` · `site/index.html` | 独立网页（Stories/关注/发布/我的） |
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
python skillfeed.py serve      # Instagram 板式信息流（会自动 build）
```

数据目录：`~/.skill-feed/`（`feed.json` / `feed.html` / `corpus/` / `feedback.jsonl`）。

## 常用命令

- `python skillfeed.py refresh [--since daily|weekly] [--force] [--intent TEXT]`
- `python skillfeed.py build [--intent TEXT]` — 不联网重生信息流 HTML
- `python skillfeed.py corpus [--max-issues N]`
- `python skillfeed.py publish-site [--out site]` — 导出 GitHub Pages 静态站
- `python skillfeed.py api [--port 8787]` — 云端 API（登录 + UGC，需 `requirements-server.txt`）
- `python skillfeed.py serve [--port 8473]`
- `python skillfeed.py check`
- `python skillfeed.py feedback`

公开站：Actions 工作流 `Refresh & Pages` 每 6 小时 refresh 并部署到  
`https://469910093-ui.github.io/skillfeed/`（`SKILLFEED_HOME` 可覆盖数据目录）。

UGC API：`server/`（FastAPI + SQLite）。本地可先 `SKILLFEED_DEV_AUTH=1`，生产配 GitHub OAuth（见 `.env.example`）。

## PRD 同步（强制）

产品真相源：`docs/PRD.md`（含 §0 变更纪律、§13 变更日志）。

当你或用户做**任何产品调优**（IA、Stories/pills、关注、排序/门禁、文案引导、存储 key、里程碑取舍等）：

1. **同批更新** `docs/PRD.md` 正文对应章节  
2. **追加** §13 变更日志一行（日期 · 摘要 · 影响）  
3. 必要时刷新 §12 开发现状对照  
4. 代码与 PRD 冲突时，**先改 PRD 再改代码**（或同 PR 内两者一起改完）  

未回写 PRD 的产品改动视为未完成，不得只改 `feed_dashboard.py` / 引擎参数就结束。

## 注意

- CTA 只有「打开 GitHub」；无 install / 不写宿主 skills 目录
- Stories = 关注动态；pills = 发现筛选（见 PRD §5.0）
- Trending 抓取失败时回退缓存并 WARN，不编造榜单
- 知识库只增不删；空 Feed 时用 corpus backup + 漏斗解释
