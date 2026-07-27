# HelloGitHub 全刊分类总结（第 1–123 期）

> 材料来自本机已同步的 HelloGitHub 官方仓库镜像 (~/.hellogithub/HelloGitHub，源：github.com/521xueweihan/HelloGitHub)，覆盖第 1–123 期正文。未对 hellogithub.com 逐期网页抓取（内容同源）；分类按各期「### 栏目名」统计。

- 期数：123（HelloGitHub01.md → HelloGitHub123.md）
- 去重后栏目数：18（含「其它」）

## 栏目总表（按条目数）

| 栏目 | 累计条目 | 出现期数 | 首期 | 末期 | 类型 |
|---|---:|---:|---:|---:|---|
| JavaScript 项目 | 570 | 123 | 1 | 123 | 语言栈 |
| Python 项目 | 506 | 123 | 1 | 123 | 语言栈 |
| Go 项目 | 444 | 119 | 3 | 123 | 语言栈 |
| 人工智能 | 328 | 104 | 9 | 123 | 主题 |
| Java 项目 | 307 | 114 | 3 | 120 | 语言栈 |
| C++ 项目 | 240 | 106 | 7 | 123 | 语言栈 |
| C 项目 | 181 | 96 | 7 | 123 | 语言栈 |
| C# 项目 | 176 | 94 | 5 | 123 | 语言栈 |
| 开源书籍 | 165 | 87 | 1 | 121 | 主题 |
| Swift 项目 | 148 | 94 | 6 | 123 | 语言栈 |
| Rust 项目 | 140 | 61 | 26 | 123 | 语言栈 |
| 其它 | 634 | 123 | 1 | 123 | 兜底 |
| Kotlin 项目 | 67 | 54 | 17 | 123 | 语言栈 |
| CSS 项目 | 62 | 50 | 1 | 110 | 语言栈（近期末见） |
| PHP 项目 | 54 | 42 | 5 | 117 | 语言栈 |
| Objective-C 项目 | 45 | 35 | 7 | 111 | 语言栈（近期末见） |
| Ruby 项目 | 30 | 28 | 8 | 99 | 语言栈（已淡出） |
| **Skills** | **11** | **3** | **121** | **123** | **主题 · 最新** |

## 两个层级（读刊结构）

1. **语言/技术栈栏目**：`X 项目`（Python / JavaScript / Go / Rust / C/C++/C# / Java / Swift / Kotlin / CSS / PHP / Objective-C / Ruby …）
2. **主题栏目**：人工智能、开源书籍、Skills、其它

## 分期变化（粗）

- **01-40**：JavaScript 项目(157), Python 项目(132), Go 项目(99), Java 项目(89), 人工智能(60), 开源书籍(49), C++ 项目(30), Objective-C 项目(26)
- **111-123**：人工智能(65), JavaScript 项目(64), Python 项目(61), Go 项目(52), Rust 项目(34), C++ 项目(33), C# 项目(31), Swift 项目(29)
- **41-80**：JavaScript 项目(199), Python 项目(163), Go 项目(159), Java 项目(130), 人工智能(91), C++ 项目(85), C 项目(67), C# 项目(56)
- **81-110**：JavaScript 项目(150), Python 项目(150), Go 项目(134), 人工智能(112), C++ 项目(92), Rust 项目(77), C 项目(71), C# 项目(68)

## Skills 栏目已见条目（第 121–123 期，共 11）

| 期 | 项目 |
|---|---|
| 121 | andrej-karpathy-skills, caveman, graphify, huashu-design |
| 122 | hyperframes, Kami, skills |
| 123 | academic-research-skills, ponytail, stop-slop, text-to-cad |

## 对 skill-feed 的含义

- 全刊主体是 **语言项目橱窗**（JS/Python/Go 霸榜），不是 skill 专刊。
- **Skills** 极新（仅 121 期起）、体量小（11 条），但是与 agent skill **最对齐**的主粮。
- **人工智能**（328 条）是第二候选池：宽召回后必须二次探测是否存在 `SKILL.md`。
- **其它**（634）+ **开源书籍** 更偏杂物/阅读，不适合当 skill Feed 主轨。
- 频道建议拆成：**Skills 主轨** / **AI 主题轨（需验 SKILL.md）** / **语言轨（逛开源，不强行当 skill）**。
