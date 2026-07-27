# Implementation Plan: skill-feed 结构对齐（spec-to-implementation 风格）

**Linked Spec**：`.cursor/skills/skill-feed/SKILL.md` + `docs/startup-self-check-quick.md` + `docs/hellogithub-source-insight.md`  
**Review**：superpowers / requesting-code-review（2026-07-27）  
**Assessment**：Needs work before next phase

## Requirements Summary

1. CTA 只到 GitHub；删除代装  
2. 多源：trending + hellogithub + search；卡片 source chip  
3. gate_profile + 空 Feed 漏斗解释  
4. 意图输入 + feedback.jsonl  
5. 与 skill-picker 运行时解耦保持

## Technical Approach

保留 `trending → skill_detect → gates/rank → feed_dashboard` 骨架；砍 `install.py` 与 `/api/install`；`G_source` 改为允许声明源集合；新增 `sources/hellogithub.py`（可先读本地 digest JSON）。

## Implementation Phases

### Phase A — 产品边界对齐（先做）

| Task | Acceptance |
|---|---|
| A1 移除/禁用 install CLI 与 POST /api/install | `skillfeed.py` 无 install；serve 无写宿主路径 |
| A2 Feed 主按钮改为「打开 GitHub」 | HTML 无安装文案；测试改断言 |
| A3 同步 AGENTS.md / docstring / TOOL_FILES | 文档与 SKILL.md 一致 |
| A4 修正 skill-picker README 交叉引用 | 不再写「一键安装」 |

### Phase B — 供给与门禁

| Task | Acceptance |
|---|---|
| B1 放宽 G_source 支持多 source 值 | hellogithub 条目不被 trending 硬拒 |
| B2 接入 HelloGitHub Skills（本地 digest 或脚本） | refresh 可产出非 trending 卡片且 chip 正确 |
| B3 gate_profile loose/standard/strict | config 生效；顶栏或 CLI 可切换 |
| B4 feed.meta 漏斗字段 | trending/探测/过门禁数进 feed.json 与空态 UI |

### Phase C — 推荐与反馈

| Task | Acceptance |
|---|---|
| C1 Feed 意图输入进 rank 查询侧 | 同意图排序变化可测 |
| C2 feedback.jsonl（useful/bad/opened_github） | 落盘字段完整；可选 CLI report |
| C3 测试：G_rel、多源、空 Feed、反馈 | unittest 绿 |

## Risks

- Trending HTML 改版 → 已有 fixture；hellogithub 月更节奏需产品预期管理  
- View-only Figma 与代码无关；安装路径 Zip Slip 随 A1 删除而消失  

## Success Criteria

- 主路径无法安装；打开 GitHub 为唯一主 CTA  
- 非空日：至少一类稳定源可填 Feed  
- 空 Feed 可解释；反馈可落盘  
