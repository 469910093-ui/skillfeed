# AGENTS.md — skill-feed 安装与引导

你正在帮用户安装 **skill-feed**（与 skill-picker **拆产品线**）。

## 产品一句话

> 从 GitHub Trending + HelloGitHub + GitHub Search 发现 skill → 门禁 → **无限下滑 Feed**（一/二级场景 + 栏目）→ **打开 GitHub**。  
> 排序：兴趣画像 + 意图 + feedback；HelloGitHub 全刊进本地 **corpus**。  
> **不代装**。用户自行安装后用 skill-picker `scan`。

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
- `python skillfeed.py serve [--port 8473]`
- `python skillfeed.py check`
- `python skillfeed.py feedback`

公开站：Actions 工作流 `Refresh & Pages` 每 6 小时 refresh 并部署到  
`https://469910093-ui.github.io/skillfeed/`（`SKILLFEED_HOME` 可覆盖数据目录）。

## 注意

- CTA 只有「打开 GitHub」；无 install / 不写宿主 skills 目录
- Trending 抓取失败时回退缓存并 WARN，不编造榜单
- 知识库只增不删；空 Feed 时用 corpus backup + 漏斗解释
