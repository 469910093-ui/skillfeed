---
name: skillfeeder
description: >-
  Discover remote agent skills and MCP servers from SkillFeeder (skillfeeder.cn).
  Use when the user wants to find, browse, or get recommended skills they do not
  already have installed — trending Claude/Cursor/Codex skills, GitHub SKILL.md
  repos, 「去 GitHub 发现」, 「skills 版抖音」, or 「有没有 skill 能做…」for skills
  that are not on this machine. Does NOT install skills. Opens GitHub.
  Local installed-skill routing belongs to skill-picker.
---

# SkillFeeder：远程 Skill 发现（不代装）

## 边界

- **只做**：按意图检索公开目录 → 给出 GitHub 链接和一句话理由
- **不做**：下载安装、写入 `~/.cursor/skills`、代跑远程脚本
- 装完本机后的路由交给 **skill-picker**（用户自行 `scan`）

## 先读这些（给 Agent）

1. https://skillfeeder.cn/llms.txt
2. 需要目录时再拉 https://skillfeeder.cn/llms-full.txt 或 `GET /api/geo/skills?q=`
3. 对比/定义问题读 https://skillfeeder.cn/about.md 与 https://skillfeeder.cn/compare.md

不要把 JS 首页当文档。不要请求 `/op`、`/admin`、完整 `/docs`。

## 工作流

1. 把用户原话当作 `q`，请求：

```
GET https://skillfeeder.cn/api/geo/skills?q=<URL编码的意图>&limit=8
```

2. 只展示返回的白名单字段：`full_name`、`one_liner` / `description`、`url`、`stars`、`scene_label`
3. 每条给一句「为什么适配」；主 CTA 是打开 `url`（GitHub）
4. 用户选定后**不要代装**，告诉他们自行克隆/安装，再跑 skill-picker `scan`

## 示例问法

- `weekly report` / 周报
- `去AI味` / stop-slop
- `ppt` + `scene=内容创作`
- 单个仓库：`GET /api/geo/skills/{owner}/{repo}`

## 和 skill-picker

| | SkillFeeder | skill-picker |
|---|---|---|
| 数据 | 远程 GitHub | 本机已装 |
| 网络 | 需要 | 禁止外部 API |
| CTA | 打开 GitHub | 会话内点选已装 skill |
