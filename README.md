# skill-feed

竖滑卡片式的 **agent skill 信息流**：多源发现 → 门禁 → 本地知识库补货 → 无限下滑刷卡 → **打开 GitHub**（不代装）。

与 [skill-picker](https://github.com/469910093-ui/Skill-picker) **拆产品线**：skill-picker 管本机已装；skill-feed 管远程发现。

## 在线网站（GitHub Pages）

公开站会由 GitHub Actions **每 6 小时自动 refresh** 并部署：

**https://469910093-ui.github.io/skillfeed/**

- 仓库：[469910093-ui/skillfeed](https://github.com/469910093-ui/skillfeed)
- 手动刷新：GitHub → Actions → **Refresh & Pages** → Run workflow
- 赞/藏目前仅保存在浏览者本机（localStorage）；服务端 UGC 另议

本地导出静态站：

```bash
python skillfeed.py refresh
python skillfeed.py publish-site --out site
# 把 site/ 丢到任意静态托管即可
```

## 云端 API（登录 + UGC）

第二步：用户可 **GitHub 登录并发布自己的 skill**，与官方发现流混排。

```bash
pip install -r requirements-server.txt
cp .env.example .env   # 填入 GitHub OAuth App 的 Client ID/Secret
# 本地无 OAuth 时可先：
#   set SKILLFEED_DEV_AUTH=1   (Windows) 或 export SKILLFEED_DEV_AUTH=1
python skillfeed.py api --port 8787
```

| 地址 | 作用 |
|---|---|
| http://127.0.0.1:8787/ | API 首页 |
| /publish | 发布页（登录后贴 SKILL.md） |
| /api/feed | UGC + Pages 官方索引混排 |
| /api/feed?source=ugc | 仅用户发布 |
| /docs | OpenAPI |

GitHub OAuth App 回调填：`{SKILLFEED_PUBLIC_URL}/auth/callback`  
（例如 `http://127.0.0.1:8787/auth/callback`）

部署到 Railway / Fly / Render：设置同样的环境变量，进程  
`uvicorn server.app:app --host 0.0.0.0 --port $PORT`。

## 一键打开信息流（本机）

```bash
cd skill-feed
python skillfeed.py corpus      # 首次：灌 HelloGitHub 全刊进知识库
python skillfeed.py refresh     # 六源联网刷新（见下表）
python skillfeed.py serve       # 打开竖滑信息流（自动 build 最新板式）
```

本地只改了 UI / 想重排时：

```bash
python skillfeed.py build [--intent "写作 去AI味"]
python skillfeed.py serve
```

数据目录：`~/.skill-feed/`（`feed.json` · `feed.html` · `corpus/` · `feedback.jsonl` · `i18n/`）。

## 中英双语卡片

`SKILL.md` 的 `description` 是写给 agent 做路由判断的（清一色 `Use when...`），
直接展示就会中英混排、且读者看不懂到底能干什么。所以 refresh / build 会多跑一层
归一化：调阿里云百炼把每条重写成**中英两份**「一句话 + 3 条亮点 + 适合谁」，
写进 `~/.skill-feed/i18n/cards.jsonl`。

- 缓存键 = `full_name` + `skill_path` + 内容 hash，内容没变不重复调模型
  （monorepo 一个仓库能展开出十几条 skill，少了 `skill_path` 它们会互相覆盖，
  每次构建都要重译一大批）
- 页面右上角 `中文 / EN` 开关，**默认中文**，选择记在 localStorage，切换不发请求
- 缺某语种时回退另一种，两种都缺回退 `SKILL.md` 原文，不留空
- 未设 `DASHSCOPE_API_KEY` 时构建不会失败，只是全部退回原文

```bash
export DASHSCOPE_API_KEY=sk-xxx
python skillfeed.py i18n              # 只补文案，不联网采集
python skillfeed.py i18n --force      # 忽略缓存全部重写
python skillfeed.py i18n --limit 5    # 先试 5 条看质量
```

百炼有两种 key：账号级的用默认域名即可；**工作空间级的（`sk-ws-…` 开头）必须配
它自己的域名**，否则会 401。域名在百炼 API-KEY 页面的 `openAiCompatible` 一栏，
填到 `~/.skill-feed/config.json` 的 `i18n_base_url`，或用环境变量：

```bash
export DASHSCOPE_BASE_URL=https://ws-xxxxxxxx.cn-beijing.maas.aliyuncs.com/compatible-mode/v1
```

CI 里配 `DASHSCOPE_API_KEY` + `DASHSCOPE_BASE_URL` 两个 secret；
缓存目录随 `actions/cache` 一起复用，所以每次定时刷新只为**新增条目**付费。

## 译稿库（飞书多维表格）

`cards.jsonl` 只是机器缓存：内容指纹一变就重译，换机器、换 CI 就没了。译稿库把
skills 和中英译稿沉到飞书多维表格，多拿两件事——

- **人工验收即锁定**：状态改成「已验收」的行，之后无论上游 `SKILL.md` 怎么改都
  不再调模型。译稿稳定，token 也不再重复烧。
- **可直接编辑**：译得不好就在表里改，改完仍是「已验收」，`pull` 回来就是你的版本。

状态机：

| 状态 | 含义 |
| --- | --- |
| 待审 | 机器刚译出，未经人看。内容指纹变了会重译 |
| 已验收 | 人工确认过。锁定，永不重译（`--force` 除外） |
| 需重译 | 人工判定译得不行，下次一定重译 |

```bash
python skillfeed.py bitable init --base-token XXXX   # 建表，一次就好
python skillfeed.py bitable pull                     # 表 → 本地，拉回验收结果
python skillfeed.py bitable push                     # 新译稿 → 表，不动已验收行
python skillfeed.py bitable sync                     # pull → i18n → push 一条龙
python skillfeed.py bitable dedupe                   # 清重复行
```

`base_token` 可以写进 `~/.skill-feed/config.json` 的 `bitable_base_token`，之后
`init` 不用再传。需要 `lark-cli` 已登录（`npm i -g @larksuite/cli`）。

日常节奏：`refresh` 之后跑 `bitable push` 把新条目送去待审；人在表里改完标已验收，
下次 `bitable pull` 拉回来，从此这些条目永不再翻译。

## 信息流怎么用

| 手势 / 入口 | 作用 |
|---|---|
| 动态圆环 | 切模式 / 一级场景；点场景可进全屏动态轮播 |
| 二级 pills | 写作润色、短视频… |
| 双击封面 / 红心 | 有用（写入 feedback + 本地 liked） |
| 拇指向下 | 不感兴趣，少推这类（写入 feedback `bad`） |
| 书签 | 收藏到 Saved Tab |
| 打开 GitHub | 主 CTA（不代装），每张卡只有这一个入口 |
| 右上角 中文 / EN | 切换卡片与界面语言，默认中文 |
| 底栏 Saved | 看本地赞过/收藏的 skill |
| 播放键或 `?demo=1` | 自动巡演 Demo（默认不自动开） |

## 数据源（refresh 六路）

`refresh` 按序拉候选 → 合并去重 → 探测 `SKILL.md` → 过门禁。卡片标 `source` chip。

| source 值 | 角色 | 数据从哪来 | 默认开关 |
|---|---|---|---|
| `github.com/trending` | 热度爆发 | 抓取 GitHub Trending | 常开 |
| `hellogithub` | 月刊稳定供给 | 本机 `~/.hellogithub/HelloGitHub` | 常开 |
| `github-search` | SKILL.md 召回 | GitHub Search API | `search_enabled: true` |
| `catalog` | 策展目录 | awesome lists + skills.sh 热榜 | `catalog_enabled: true` |
| `xiaohongshu` | 中文社区热议 | `~/.skill-feed/xhs/mentions.json` + 种子 | `xhs_enabled: true` |
| `the-download` | GitHub The Download 点名 MCP/Skills | `scripts/ingest_the_download.py` · [`docs/the-download-mcp-skills.md`](docs/the-download-mcp-skills.md) | 人工策展灌库 |
| `corpus` | 本地知识库补货 | `~/.skill-feed/corpus/` | 常开 |

合并优先级：trending > hellogithub > catalog > xiaohongshu > github-search > corpus。  
星数豁免源：hellogithub / corpus / github-search / catalog / xiaohongshu。  
小红书采集：`python skillfeed.py xhs-crawl [--keyword TEXT] [--max N]`。

## 配置

见 `config_defaults.json` → 复制到 `~/.skill-feed/config.json`。常用：`gate_profile`、`soft_skill_limit`、`github_token`、`search_enabled` / `catalog_enabled` / `xhs_enabled`。

## 测试

```bash
python -m unittest discover -s tests
```

## 第三方素材

界面图标有一部分来自 Feather Icons（MIT）与 Material Icons（Apache-2.0），
出处、许可与「哪个图标是逐字节相同、哪个是衍生版」逐条列在 [`NOTICE`](NOTICE)。
品牌色板与字体的取值依据见 [`docs/brand-tokens.md`](docs/brand-tokens.md)。
