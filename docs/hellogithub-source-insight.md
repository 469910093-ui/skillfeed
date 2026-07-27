# HelloGitHub 源头洞察（对照 skill-feed）

> 按 hellogithub skill：已 `update-repo` + `prepare-digest`（第 123 期）  
> 官方：https://hellogithub.com/periodical/volume/123

## 关键发现

第 123 期在 **Skills 专栏** 稳定产出多条 agent skill 包，例如：

| 项目 | GitHub | 一句话 |
|---|---|---|
| text-to-cad | https://github.com/earthtojake/text-to-cad | 自然语言生成 CAD 的技能包 |
| academic-research-skills | https://github.com/Imbad0202/academic-research-skills | 学术研究 Claude 技能包 |
| ponytail | https://github.com/DietrichGebert/ponytail | 让 AI 少写代码、防过度工程 |
| stop-slop | https://github.com/hardikpandya/stop-slop | 去 AI 味写作技能包 |

同期限 AI/agent 生态条目 14+（digest 候选），而同日全局 Trending **可能 0 个 SKILL.md**。

## 对 skill-feed 的产品含义

| 源 | 角色 | 节奏 |
|---|---|---|
| `github.com/trending` | 热度 / 爆发 | 日更，skill 密度低 |
| HelloGitHub Skills | **稳定 skill 供给** | 月更（约 28 号），密度高 |
| GitHub Search `path:SKILL.md` | 补全 / 召回 | 按需，注意 rate limit |

**结论**：G_source 不宜只等于「出现在当日 Trending」。建议改为：

- `source ∈ {trending, hellogithub, search}` 均可进 Feed  
- UI 用 chip 标明来源  
- 排序：会话/意图相关分优先，其次 stars / 今日增量 / 月刊新鲜度

HelloGitHub 是 **Tier B 线索源**：进 Feed 前仍应用 raw `SKILL.md` 探测 + G_parse；点进 GitHub 后由用户自行判断。
