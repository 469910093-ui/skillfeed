"""锁住发布 workflow 的配置来源，防止手抄字典再次漂移。

背景：pages.yml 里曾经手抄了一份完整的 config 字典。抄的 14 个键里有 6 个已经和
config_defaults.json 对不上（hg_max_issues 8/12、corpus_feed_limit 300/400、
soft_skill_limit 30/40、search_max_repos 30/40、search_per_page 20/25、
search_probe_limit 10/25），而且从 diff 上看不出哪个是有意调小、哪个是抄漏了。

这里不去断言具体数值——那样每次调预算都要改测试，测试会先被改烂。断言的是
「配置必须从默认值派生」「留在 workflow 里的每个覆盖都必须真的不同于默认值」，
让"静默复制"这种写法在 CI 上就过不去。
"""

import ast
import json
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "pages.yml"

# CI 环境本身决定的键：路径由 runner 的 checkout 位置定，UA 用来让上游区分
# 定时公开构建，interest_from 置空是为了让 G_rel 的 SKIP 是明确声明而非副作用。
ENV_SPECIFIC_KEYS = {"hellogithub_repo", "user_agent", "interest_from"}


def _dict_literal(text: str, name: str) -> str:
    """抠出 `name = {...}` 的字面量，按花括号配平找结尾。"""
    m = re.search(rf"^\s*{name}\s*=\s*\{{", text, re.M)
    if not m:
        raise AssertionError(f"workflow 里找不到 `{name} = {{...}}`")
    start = m.end() - 1
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise AssertionError(f"`{name}` 的花括号没配平")


class TestPublishWorkflowConfig(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.yml = WORKFLOW.read_text(encoding="utf-8")
        cls.defaults = json.loads(
            (REPO / "config_defaults.json").read_text(encoding="utf-8")
        )

    def test_config_is_derived_from_repo_defaults(self):
        """必须以 config_defaults.json 打底，而不是自己另起一份。

        断言的是真的把它读进了 cfg，不是"文件里出现过这个串"——那个串在
        paths: 触发清单和注释里也有，只查子串的话派生逻辑被删掉测试照样绿。
        变异测试就是这么抓出这条断言原本是空壳的。
        """
        self.assertRegex(
            self.yml,
            r"cfg\s*=\s*json\.loads\([^\n]*config_defaults\.json",
            "发布配置没有从仓库默认值派生，漂移会再次发生",
        )

    def test_no_hand_copied_full_config_dict(self):
        """`cfg = {` 是那份手抄字典的写法，不许回来。"""
        self.assertIsNone(
            re.search(r"^\s*cfg\s*=\s*\{", self.yml, re.M),
            "workflow 又开始手写完整 config 字典了；请改成读默认值 + 显式覆盖",
        )

    def test_budget_overrides_all_actually_differ_from_defaults(self):
        """预算档里每个键都必须真的不同于默认值。

        值相同的键是纯复制——今天无害，等默认值一改它就变成静默漂移。发现即删。
        """
        budget = ast.literal_eval(_dict_literal(self.yml, "budget"))
        self.assertTrue(budget, "预算档为空，这个测试就失去意义了")
        for key, value in budget.items():
            self.assertIn(key, self.defaults,
                          f"预算档的 {key} 不在 config_defaults.json 里——键名写错会静默无效")
            self.assertNotEqual(
                value, self.defaults[key],
                f"预算档的 {key}={value} 与默认值相同，属纯复制，请从 workflow 删掉",
            )

    def test_env_specific_overrides_are_the_declared_set(self):
        """环境相关的覆盖就这三个；多出来的要么该进预算档，要么该进默认值。"""
        block = _dict_literal(self.yml, "ci_only")
        keys = set(re.findall(r'^\s*"([a-z0-9_]+)"\s*:', block, re.M))
        self.assertEqual(keys, ENV_SPECIFIC_KEYS)

    def test_every_env_specific_key_is_a_real_config_key(self):
        for key in ENV_SPECIFIC_KEYS:
            self.assertIn(key, self.defaults)

    def test_workflow_rebuilds_when_defaults_change(self):
        """默认值改了却不重新发布，等于改了没生效。"""
        paths = re.search(r"paths:\n(.*?)\n\S", self.yml, re.S)
        self.assertIsNotNone(paths, "找不到 push 触发的 paths 段")
        self.assertIn("config_defaults.json", paths.group(1))


if __name__ == "__main__":
    unittest.main()
