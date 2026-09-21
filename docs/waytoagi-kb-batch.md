# 通往AGI之路 · 知识库批次入库（WaytoAGI → skill-feed）

> 批次：用户粘贴的多期「知识库更新」列表（2026-07～08 窗口汇总）  
> **底表（飞书）：** 能落到 GitHub 的一律进资源清单（skill / agent / CLI / 书单都要），使命是全、准确。  
> **Feed：** skill-feed 再按门禁筛（skill 形 + 可判定的 MCP）；底表有、Feed 没有 = 正常。  
> 纯资讯/白皮书/活动且**无仓可核**的，无法进底表，只留本文备忘。  
> 硬性规定：入库失败或 0 条成功 → **必须通知用户**，禁止假成功。

## 命令

```bash
cd D:\Users\yaowenliang\Projects\skill-feed
python scripts/ingest_waytoagi.py --merge-feed --push-bitable
python skillfeed.py build
python skillfeed.py publish-site --out site
```

飞书表：https://trip.larkenterprise.com/base/XLkFbdhtqazDqvsaH7vczCmdnmf  
（表 `tbltZKd8PQgV4RD9` · 来源=策展目录 · 数据池=知识库 · 关键词含 WaytoAGI）

## 本批入库重点（Skills / GitHub）

| 提炼 | GitHub | 类型 |
|------|--------|------|
| 55 个 AI 视频 Skill | `Pluviobyte/rnskill`（文内另引 `dontbesilent2025/dbskill`、`xiaohuailabs/xiaohu-video-translate`） | skill |
| 苍何 Codex 换肤开源 | `freestylefly/codex-themes` + `freestylefly/canghe-skills` | toolkit/skill |
| 云舒最常用 Skills | `yunshu0909/yunshu_skillshub` | skill |
| 成峰首页设计 Skill | `Agentchengfeng/chengfeng-landingpage` | skill |
| X 资讯扫描器 | `simonlin000/x-scan` | toolkit |
| Listing 质检 Skill | `buluslan/amazon-listing-doctor` | skill |
| SVG 信息图 | `antvis/Infographic` | toolkit |
| YC 多 Agent QM | `yc-software/qm` | agent |
| OpenCode | `anomalyco/opencode` | agent |
| Scrapling 采集 | `D4Vinci/Scrapling` | toolkit |
| awplanet 3D 导演台 | `awplanets/awplanet` | toolkit |
| awesome-open-llms | `liucongg/awesome-open-llms` | oss |
| 本周 TOP 中可装技能/agent | `ibelick/ui-skills`、`MoonshotAI/kimi-cli`、`MoonshotAI/kimi-code`、`bojieli/ai-agent-book`、`1jehuang/jcode`、`agegr/pi-web` | 混合 |

## 进了底表、未进主 Feed（门禁筛掉，正常）

`codex-themes`、`yc-software/qm`、`opencode`、`awplanet`、`awesome-open-llms`、`kimi-cli`、`kimi-code`、`jcode`、`pi-web` 等：底表保留，Feed 因不是 skill 形 / 未过探测而不录入。

## 无法进底表（无稳定 GitHub 可核）— 选题备忘

Dan Koe 记忆法、GEO 公开课 / Fan-out Rank、Graph Engineering、Starter Story、上下文工程指南（附助手但无公开仓）、老金 Codex 技巧、Kimi K3 开放日文、GMI 白皮书、Her 产品、Top 论文、角色演技提示词、AI 音乐周刊、China Summer 活动、架构演进文、Codex 教程、微短剧灵感库、具身智能方法论、Agent 学习指南、刘小排 Codex×Pro 观点、Sif 电商 Agent、Midjourney、物理/创业叙事、LatePost Lovart、卡尔工作流、冷逸五门课、学英语手册、Magnific 手册、Loop Engineering、宝玉 TL→EM、李飞飞 a16z、文兄 Kimi Prompt、博物馆活动、Seedance/H3/DeepSeek 发布与手册、硬件训练营、测评文、Codex Microdevice 拆解等。

> 若后续 Wiki 补了 GitHub 链接，追加到 `scripts/ingest_waytoagi.py` 的 `CURATED` 再跑即可。
