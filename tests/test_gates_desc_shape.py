"""G_parse 的 description 形态校验：拦得住解析残留，且不误伤真实描述。

这一轮是「收紧」。上一轮放宽（块标量解析修复）救回 81 条被误拒的优质内容，
教训是被拒的那批平均质量高于通过的那批——所以这里的误伤用例比拦截用例更重要，
下面 KEEP_* 全部取自真实语料原文，不要改写成手写的简化版本。
"""

from __future__ import annotations

import unittest

import gates
import rank

# 真坏值：comeonzhj/Auto-Redbook-Skills :: skills/xhs-note-creator/SKILL.md。
# 仓库里这个文件是 git 符号链接，raw.githubusercontent 直接把 symlink 的 blob
# 内容（目标路径）当正文返回，于是整份 SKILL.md 正文就是这一行。长度 14，
# 只看长度的旧规则放它过关，最后当描述显示在卡片上。
SYMLINK_RESIDUE = "../../SKILL.md"

# 必须放行的真实描述。前三条是形态上最接近坏值的：
#   - rembg：中文 + 斜杠 + 没有空格 —— 如果路径判定不先要求 ASCII 就会误伤
#     （\w 在 Python 正则里匹配汉字）
#   - TCP-IP-NetworkNote：书名里的斜杠
#   - TopList：描述里嵌了一个真 URL，但整体不是 URL
KEEP_REAL = (
    "简单实用的删除图像背景/抠图工具",
    "《TCP/IP 网络编程》学习笔记。除了笔记还包含书中的代码实现和课后习题回答",
    "各大网站热门头条的聚合网站。[在线预览](https://mo.fish/)",
    "一个文件的 C++ HTTP/HTTPS 库。这是一个用 C++11 写的仅头文件、跨平台的库。",
    "Rewrite AI-sounding text so it reads naturally without changing what it says.",
    "Generate DESIGN.md and enforce premium, anti-generic UI standards.",
)


class TestDescriptionShape(unittest.TestCase):
    def test_symlink_residue_rejected(self):
        self.assertEqual(
            gates.description_shape_reason(SYMLINK_RESIDUE, "xhs-note-creator"),
            "shape_pure_path",
        )

    def test_bad_shapes(self):
        cases = {
            "shape_pure_path": ["../../SKILL.md", "references/style.md", r"docs\api\x.md"],
            "shape_pure_url": ["https://example.com/a/b", "www.example.com/skill"],
            "shape_pure_filename": ["SKILL.md", "pyproject.toml", "build_script.sh"],
            "shape_no_word_char": ["----------", "。。。。。。。。。。", "!!!!!!!!!!!!"],
        }
        for want, values in cases.items():
            for v in values:
                with self.subTest(value=v):
                    self.assertEqual(gates.description_shape_reason(v, "whatever"), want)

    def test_same_as_name_rejected(self):
        self.assertEqual(
            gates.description_shape_reason("Brand Guardian", "brand guardian"),
            "shape_same_as_name",
        )

    def test_real_descriptions_pass(self):
        for d in KEEP_REAL:
            with self.subTest(desc=d[:30]):
                self.assertEqual(gates.description_shape_reason(d, "x"), "")

    def test_produced_file_name_is_not_a_path(self):
        """产出物文件名放行：skill 的能力本身就是生成某个文件时，写出它是合理的。

        i18n 的违禁词表已经踩过这个坑（旧的裸 `\\.md\\b` 让「生成 DESIGN.md」
        这类描述逻辑上不可能通过）。这里只在「整个值就是一个 token」时才判，
        所以带上下文的产出物文件名不受影响。
        """
        self.assertEqual(
            gates.description_shape_reason("产出一份 DESIGN.md，含配色与字号规范", "x"),
            "",
        )


class TestGateWiring(unittest.TestCase):
    """形态校验要真的接在 G_parse 上，并沿用被拒明细那套可观测字段。"""

    def _run(self, **over):
        row = {
            "full_name": "comeonzhj/Auto-Redbook-Skills",
            "source": "xiaohongshu",
            "stars": 100,
            "name": "xhs-note-creator",
            "description": SYMLINK_RESIDUE,
            "keywords": "",
            "body_preview": SYMLINK_RESIDUE,
            "skill_path": "skills/xhs-note-creator/SKILL.md",
            "url": "https://github.com/comeonzhj/Auto-Redbook-Skills",
        }
        row.update(over)
        return gates.run_gates(
            [row],
            trending_names=set(),
            min_stars=20,
            min_rel=0.05,
            interest_toks=rank.load_interest_tokens(None),
        )

    def test_rejected_by_g_parse(self):
        passed, summary = self._run()
        self.assertEqual(passed, [])
        self.assertEqual(summary["rejected"]["G_parse"], 1)

    def test_reject_detail_is_actionable(self):
        _passed, summary = self._run()
        detail = next(d for d in summary["details"] if d["gate"] == "G_parse")
        self.assertEqual(detail["reason"], "shape_pure_path")
        self.assertEqual(detail["skill_path"], "skills/xhs-note-creator/SKILL.md")
        self.assertEqual(detail["source"], "xiaohongshu")
        # 实际取值要落在明细里，否则下次形态变了还得重跑 36 分钟的 refresh 才知道
        self.assertEqual(detail["description"], SYMLINK_RESIDUE)

    def test_parse_reasons_counter(self):
        _passed, summary = self._run()
        self.assertEqual(summary["parse_reasons"], {"shape_pure_path": 1})

    def test_good_row_still_passes(self):
        passed, summary = self._run(
            description="把小红书笔记草稿改写成可直接发布的正文，含标签与合规自检。",
        )
        self.assertEqual(len(passed), 1)
        self.assertEqual(summary["parse_reasons"], {})


if __name__ == "__main__":
    unittest.main()
