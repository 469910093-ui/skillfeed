# skill-feed

Instagram 板式的 **agent skill 信息流**：多源发现 → 门禁 → 本地知识库补货 → 无限下滑刷卡 → **打开 GitHub**（不代装）。

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

## 一键打开信息流（本机）

```bash
cd skill-feed
python skillfeed.py corpus      # 首次：灌 HelloGitHub 全刊进知识库
python skillfeed.py refresh     # 联网刷新（trending + HG + Search）
python skillfeed.py serve       # 打开 IG 风信息流（自动 build 最新板式）
```

本地只改了 UI / 想重排时：

```bash
python skillfeed.py build [--intent "写作 去AI味"]
python skillfeed.py serve
```

数据目录：`~/.skill-feed/`（`feed.json` · `feed.html` · `corpus/` · `feedback.jsonl`）。

## 信息流怎么用

| 手势 / 入口 | 作用 |
|---|---|
| Stories 圆环 | 切模式 / 一级场景；点场景可进全屏 Story 轮播 |
| 二级 pills | 写作润色、短视频… |
| 双击封面 / 红心 | 有用（写入 feedback + 本地 liked） |
| 书签 | 收藏到 Saved Tab |
| 打开 GitHub | 主 CTA（不代装） |
| 底栏 Saved | 看本地赞过/收藏的 skill |
| 播放键或 `?demo=1` | 自动巡演 Demo（默认不自动开） |

## 数据源

| source | 角色 |
|---|---|
| trending | 热度 |
| hellogithub | 月刊 Skills / AI |
| github-search | SKILL.md 召回（建议 `GITHUB_TOKEN`） |
| corpus / soft | 知识库线索卡（标「线索」）也能刷 |

## 配置

见 `config_defaults.json` → 复制到 `~/.skill-feed/config.json`。常用：`gate_profile`、`soft_skill_limit`、`github_token`。

## 测试

```bash
python -m unittest discover -s tests
```
