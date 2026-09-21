# The Download → skill-feed：MCP / Skills 策展笔记

> 信源：GitHub 官方频道播放列表 [The Download Show!](https://www.youtube.com/playlist?list=PL0lo9MOBetEE0goMLEl97vO7slruNVj43)  
> 入库脚本：`scripts/ingest_the_download.py`  
> 首次灌库：2026-09-08

## 范围

只收录节目**点名且能落到 GitHub 仓库**的 MCP / Skills / Agent 工具链（及强相关 SDK）。  
产品 changelog、模型发布、纯趣味 Project pick（如像素城）不进本清单。

## 策展表

| 仓库 | 类型 | 节目点名 | 集号（playlist index） |
|------|------|----------|------------------------|
| github/github-mcp-server | mcp | GitHub MCP Server / Registry / Remote | 024, 031, 036 |
| modelcontextprotocol/servers | mcp | MCP 生态 / funeral 讨论背景 | 013, 024, 036 |
| modelcontextprotocol/python-sdk | mcp | MCP SDK | 036 |
| modelcontextprotocol/typescript-sdk | mcp | MCP SDK | 036 |
| PrefectHQ/fastmcp | mcp | FastMCP「funeral」梗 | 013 |
| docker/mcp-gateway | mcp | Docker MCP Toolkit | 034 |
| microsoft/azure-devops-mcp | mcp | Azure DevOps MCP | 031 |
| a2aproject/A2A | protocol | A2A 进 Agentic AI Foundation | 002 |
| a2aproject/a2a-python | protocol | A2A SDK | 002 |
| github/awesome-copilot | skill | Copilot CLI / 社区 skills | 014, 024 |
| github/spec-kit | toolkit | Universe / AgentKit 同档开源工具 | 023 |
| openclaw/openclaw | agent | OpenClaw 本机 agent | 015, 016 |
| VoltAgent/awesome-openclaw-skills | skill | OpenClaw skills 合集 | 015, 016 |
| openai/openai-agents-python | agent | AgentKit 生态 | 023 |
| openai/openai-agents-js | agent | AgentKit 生态 | 023 |
| TanStack/ai | toolkit | TanStack AI alpha | 010 |
| omacom/ttfx | oss | 终端动画 Project pick | 002 |
| louisabraham/load-bearing | research | AI PR 词汇分析 | 001 |

## 命令

```bash
cd skill-feed
# 需本机 gh 已登录（或 GITHUB_TOKEN）
python scripts/ingest_the_download.py --merge-feed --push-bitable
python skillfeed.py build
python skillfeed.py publish-site --out site
# 公开站：Actions → Refresh & Pages，或 push site 分支按仓库既有流程
```

## 与 catalog 关系

`catalog_sources.DEFAULT_SEED_REPOS` / `FORCE_PROBE_REPOS` 已加入本表中带 skills 探测价值的仓，  
日常 `refresh` 会继续强制探测；本脚本负责**带 The Download 出处元数据**写入 corpus / 飞书。

## 诚实声明

- 星数与描述以入库当日 `gh api` 为准，会漂移。  
- 多数 MCP 仓**没有**根目录 `SKILL.md`；不再假装成 skill。`kind=mcp` 可进主 Feed（仓名/描述可判定 + 星数门槛）；`agent/protocol` 仍先留底表/知识库。  
- Cloudflare MCP 检测、GitHub MCP Registry 产品页无独立开源仓时，用 `github-mcp-server` + `modelcontextprotocol/*` 代表。
