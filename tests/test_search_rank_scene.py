import tempfile
import unittest
from pathlib import Path
from unittest import mock

import feed_dashboard
import github_search
import i18n
import rank
import scene


class TestSceneL2(unittest.TestCase):
    def test_writing_l2(self):
        item = scene.apply_scene({
            "name": "stop-slop",
            "description": "去掉 AI 味写作技能包，润色文案减少套话",
            "keywords": "writing",
            "hg_section": "Skills",
        })
        self.assertEqual(item["scene"], "content")
        self.assertEqual(item["scene_l2"], "writing")
        self.assertEqual(item["scene_l2_label"], "写作润色")

    def test_l2_tree(self):
        tree = scene.scene_l2_tree()
        self.assertIn("content", tree)
        ids = {c["id"] for c in tree["content"]}
        self.assertIn("writing", ids)
        self.assertIn("short-video", ids)


class TestSceneKeywordNoise(unittest.TestCase):
    """关键词是子串匹配，裸英文短词会误伤。这里锁住已经踩过的坑。

    两层防护，缺一不可：
      1. test_no_short_bare_ascii_keywords 是通用地板：扫遍所有子串匹配常量，
         任何新加的 < 4 字符裸词都会被自动拦住，不必等下一轮人工审计发现。
      2. LANDMINES_L1 / LANDMINES_L2 是具体案卷：记录已经造成过误判的词，
         包括长度 >= 4 因而通不过通用断言的（skill / writing / research）。

    历史事故（每条都曾把大批条目吸到错误行业）：
      skill/skills  → skill_path 必然含 skill，一度让 71% 落进 Agent工具链
      script        → JavaScript / TypeScript
      ui            → build 131 次 / guidelines 74 次，87% 误命中
      ux            → linux / nuxt / luxury，80% 误命中
      motion        → promotion / emotion
      writing/copy  → "before writing code" / copyright
      bi            → accessibility / capabilities / mobile，真词命中 0
      wow / mom     → "wow experience" / moment(s)，真词命中 0
      api           → 一级禁用（见下），二级放行
    """

    # 一级禁用：一级是跨行业竞争，一个词误命中就把整张卡片扔进错误行业，
    # 而且行业筛选会让用户永远筛不到它，代价比二级大得多。
    LANDMINES_L1 = {
        "agent-tooling": ("skill", "skills"),
        "content": ("script", "writing", "copy"),
        "design": ("ui", "ux", "motion", "design"),
        "data-review": ("bi", "wow", "mom"),
        # api 同时出现在这里和 SHORT_WORD_ALLOWLIST：语料里 100 篇含 "api"，
        # 绝大多数是「顺带调了个 API」的内容/设计类 skill，放进一级会把它们
        # 全吸到工程开发；但一级已定为 engineering 之后，用它区分 SDK/API 子类
        # 是准确的。所以一级禁、二级放。
        "engineering": ("api", "bom"),
        "collab": ("任务",),
        "research": ("research",),
        "quality": ("qa",),
    }

    # 二级禁用：key 是父级 id，值里的词不许出现在该父级的任何子类关键词里。
    #   tween  → 19 篇命中 100% 来自 between，一次真词都没有。它有 5 个字符，
    #            通不过长度断言，只能靠这份案卷拦住
    #   motion → remotion 118 次、emotional 5 次；promotion 是一级踩过的雷
    LANDMINES_L2 = {
        "design": ("ui", "ux", "motion", "tween"),
        "data-review": ("bi", "wow", "mom"),
        "engineering": ("bom",),
        "quality": ("qa",),
        "agent-tooling": ("skill", "skills"),
        "content": ("script", "writing", "copy"),
    }

    # 长度 < 4 的裸词白名单。收录标准：拿 ~/.skill-feed 的 766 篇真实语料实测，
    # 「吞掉它的长词」语义仍然正确，因此子串命中不构成误判。每条都写明依据。
    SHORT_WORD_ALLOWLIST = {
        "api": "100 篇命中里 85 篇是真词；apis/openapi/fastapi 语义一致，"
               "唯一真污染是 scraping/rapid 内嵌 api（8 篇，<8%）。仅限二级",
        "aws": "8 篇命中里 7 篇真词；唯一污染是 flaws，而全称 amazon web services 0 命中",
        "bug": "33 篇命中全部落在 bugs/debug/debugging/bugfix 上，语义仍是质量问题",
        "gmv": "766 篇里零命中零污染；没有任何英文长词包含 gmv 这个字母序列",
        "mcp": "42 篇真词命中，唯一长词 fastmcp 仍然是 MCP",
        "pcb": "吞掉它的 jlcpcb/pcbway/pcbs 全是 PCB 打样厂或复数形式",
        "ppt": "吞掉它的 pptx/pptxgenjs 仍然是 PowerPoint",
        "sdk": "只被 sdks/awsjavascriptsdk 吞掉",
        "sql": "被 sqlite/mysql/postgresql/nosql/sqlalchemy 吞掉——"
               "它们本身都是数据库，归到「云与部署」仍然正确",
    }

    MIN_BARE_LEN = 4
    # 带分隔符的词组不会被长单词吞掉（"ui/ux" 不可能藏在 build 里），豁免长度检查。
    SEPARATORS = " /-_.:"

    @staticmethod
    def _all_keyword_groups():
        """所有走子串包含匹配的常量，一个都不能漏。"""
        for sid, kws in scene.RULES:
            yield f"RULES[{sid}]", kws
        for parent, children in scene.SCENES_L2.items():
            for cid, _label, kws in children:
                yield f"SCENES_L2[{parent}/{cid}]", kws
        yield "_PATH_DESIGN_KEYS", scene._PATH_DESIGN_KEYS

    def test_no_short_bare_ascii_keywords(self):
        """通用断言：短于 4 字符且无分隔符的 ASCII 裸词，必须在白名单里。"""
        for where, kws in self._all_keyword_groups():
            for kw in kws:
                if not kw.isascii():
                    continue  # 中文词没有子串歧义问题，别按 ASCII 词边界去卡它
                if any(c in kw for c in self.SEPARATORS):
                    continue
                if len(kw) >= self.MIN_BARE_LEN:
                    continue
                self.assertIn(
                    kw, self.SHORT_WORD_ALLOWLIST,
                    f"{where} 出现裸短词 {kw!r}：子串匹配下它会被更长的单词吞掉。"
                    f"要么换成带空格/斜杠的词组，要么拿真实语料实测后"
                    f"加进 SHORT_WORD_ALLOWLIST 并写明理由",
                )

    def test_no_bare_substring_keywords_l1(self):
        rules = dict((sid, kws) for sid, kws in scene.RULES)
        for sid, banned in self.LANDMINES_L1.items():
            for kw in banned:
                self.assertNotIn(
                    kw, rules.get(sid, ()),
                    f"一级 {sid} 不该出现裸词 {kw!r}：它是常见词的子串，会大面积误判",
                )

    def test_no_bare_substring_keywords_l2(self):
        """上一轮漏的就是这条：只查了 RULES，L2 的裸词地雷全放过去了。"""
        for parent, banned in self.LANDMINES_L2.items():
            for cid, _label, kws in scene.SCENES_L2.get(parent, []):
                for kw in banned:
                    self.assertNotIn(
                        kw, kws,
                        f"二级 {parent}/{cid} 不该出现裸词 {kw!r}："
                        f"二级徽标会被前端写成「因为 · xxx」的推荐理由，判错等于对用户说假话",
                    )

    def test_real_corpus_false_positives_do_not_classify(self):
        """反例取自 ~/.skill-feed 语料里真实存在的措辞，不是编造的样本。

        每条括号里是修复前踩的雷：某个裸短词藏在这些常见长词里。
        """
        cases = [
            # ui ← build / guidelines / building / requirements
            ("design", "build the project following the repository guidelines", "figma"),
            ("design", "requirements for building a suite of guides", "figma"),
            # ux ← linux / nuxt / tmux / luxury
            ("design", "run on linux with nuxt and tmux", "figma"),
            # bi ← accessibility / capabilities / mobile / compatibility
            ("data-review", "audit accessibility and mobile compatibility", "bi"),
            ("data-review", "describe the capabilities and observability of the agent", "bi"),
            # wow / mom ← "wow" experience / moment(s)
            ("data-review", 'create a delightful, unexpected "wow" experience', "weekly"),
            ("data-review", "capture the best moments of the session", "weekly"),
            # qa ← 语料里没有污染源，但 2 字符裸词本身就是雷，撤掉后不该再有人靠它命中
            ("quality", "planning, review, qa, shipping, debugging, docs", "testing"),
            # tween ← between（动效桶如果收了裸 tween，半个语料都会变成动效）
            ("design", "choose between the two layout options", "motion"),
            # motion ← remotion 只该由 remotion 本身命中，emotional 不该算动效
            ("design", "write emotional copy for the landing page", "motion"),
        ]
        for parent, desc, must_not in cases:
            got, _conf, why = scene.tag_scene_l2({"name": "x", "description": desc}, parent)
            self.assertNotEqual(
                got, must_not,
                f"{desc!r} 在 {parent} 下被误判成 {must_not}（{why}）",
            )

    def test_real_corpus_true_positives_still_classify(self):
        """裸词换成词组后不能把召回砍到零：这些也全是语料里的真实措辞。"""
        cases = [
            ("design", "生成高美感前端 ui 设计原型，覆盖 ui/ux 与视觉层次", "figma"),
            ("design", "elite ux/ui & advanced gsap motion engineer", "figma"),
            ("design", "做原型、ui mockup、导出 mp4，产品/ux设计师适用", "figma"),
            ("data-review", "用商业智能看板追踪核心指标与报表", "bi"),
            ("engineering", "bom management and jlcpcb assembly for kicad projects", "hardware"),
            ("quality", "跑 unittest 做回归测试与验证", "testing"),
            ("design", "渲染 Remotion 动画视频或单帧画面", "motion"),
            ("design", "用原子动效规则或预设蓝图，一键生成跨引擎动画", "motion"),
        ]
        for parent, desc, want in cases:
            got, _conf, why = scene.tag_scene_l2({"name": "x", "description": desc}, parent)
            self.assertEqual(
                got, want,
                f"{desc!r} 在 {parent} 下期望 {want}，实际 {got!r}（{why}）",
            )

    def test_wow_no_longer_pulls_whimsy_into_data_review(self):
        """语料里唯一含 "wow" 的条目是惊喜感 skill，不该落进「数据与复盘」。"""
        got = scene.apply_scene({
            "name": "whimsy-injector",
            "description": 'create a delightful, unexpected "wow" experience for the user',
        })
        self.assertNotEqual(got["scene"], "data-review", got["scene_why"])

    def test_skill_path_does_not_decide_scene(self):
        """只有 skill_path 不同的两条，行业判定必须一致。"""
        base = {
            "name": "xhs-note-creator",
            "description": "把选题一键转成小红书图文，含封面和文案",
        }
        bare = scene.apply_scene(dict(base, skill_path="SKILL.md"))
        nested = scene.apply_scene(
            dict(base, skill_path="skills/xhs-note-creator/SKILL.md")
        )
        self.assertEqual(bare["scene"], nested["scene"])
        self.assertEqual(bare["scene"], "content")

    def test_engineering_not_swallowed_by_content_or_design(self):
        cases = [
            ("azure-vm-pricing", "对比 Azure 虚拟机价格并推荐部署方案", "engineering"),
            ("tsdown", "极速打包 TypeScript 库并生成类型声明", "engineering"),
            ("finishing-a-branch", "自动验证测试并安全合并开发分支", "quality"),
            ("assess-covariance", "评估协方差估计方法的可靠性与统计性能", "data-review"),
            ("wiki-cli", "安全读取 Obsidian 本地知识库内容", "research"),
        ]
        for name, desc, want in cases:
            got = scene.apply_scene({"name": name, "description": desc})
            self.assertEqual(
                got["scene"], want,
                f"{name} 期望 {want}，实际 {got['scene']}（{got['scene_why']}）",
            )

    def test_no_l2_when_nothing_matches(self):
        """一个二级关键词都没命中时留空，不能硬贴第一个子类。"""
        got = scene.apply_scene({
            "name": "mystery-tool",
            "description": "部署到云端",
        })
        self.assertEqual(got["scene"], "engineering")
        self.assertEqual(got["scene_l2"], "infra")

        vague = scene.tag_scene_l2({"name": "zzz", "description": "zzz"}, "research")
        self.assertEqual(vague[0], "")


class TestSceneL2Motion(unittest.TestCase):
    """design 下的「动效动画」桶。fixture 全部取自 ~/.skill-feed 真实条目。"""

    def test_bucket_is_reachable_from_tree(self):
        """前端 chips 是从 scene_l2_tree() 渲染的，新桶必须带中英标签出现在树里。"""
        kids = {c["id"]: c for c in scene.scene_l2_tree()["design"]}
        self.assertIn("motion", kids)
        self.assertEqual("动效动画", kids["motion"]["label"])
        self.assertEqual("Motion & Animation", kids["motion"]["label_en"])

    def test_remotion_family_lands_in_motion(self):
        """这批条目修复前全是无二级，是「无二级」的最大来源。

        字段值照抄 ~/.skill-feed 里的真实条目（含 i18n 产出的中文字段，
        它们才是分类的主要信号），不要精简——精简掉的往往正是决定性的那一条。
        """
        for name, desc, zh, who in [
            ("remotion-render", "Export a Remotion video",
             "渲染 Remotion 动画视频或单帧画面", "Remotion 视频开发者"),
            ("remotion-studio", "Open Remotion Studio",
             "启动 Remotion 视频预览工作室并打开浏览器", "Remotion 视频开发者"),
            ("hyperframes-core", "the HyperFrames composition contract",
             "用标准 HTML 构建可精准定时、可寻址播放的视频项目。", "视频前端工程师"),
            ("vercel-react-view-transitions",
             "implementing smooth animations using react's view transition api",
             "用 View Transition API 实现页面跳转、共享元素和列表重排的丝滑动画", ""),
        ]:
            got = scene.apply_scene({
                "name": name, "description": desc, "one_liner_zh": zh,
                "who_for_zh": who, "skill_path": f"skills/{name}/SKILL.md",
            })
            self.assertEqual("design", got["scene"], got["scene_why"])
            self.assertEqual("motion", got["scene_l2"], got["scene_l2_why"])
            self.assertEqual("动效动画", got["scene_l2_label"])

    def test_framework_name_alone_reaches_the_bucket(self):
        """只说得出框架名的 skill 也要能走到动效桶：二级认得而一级不认，
        等于这个二级桶对它们不存在。"""
        for zh in ["用 hyperframes 组合视频片段", "接入 lottie 播放矢量动效",
                   "用 gsap 编排滚动时间线"]:
            got = scene.apply_scene({"name": "x", "description": "", "one_liner_zh": zh})
            self.assertEqual("design", got["scene"], got["scene_why"])
            self.assertEqual("motion", got["scene_l2"], got["scene_l2_why"])

    def test_motion_does_not_steal_static_design(self):
        """动效桶排在 design 子类最后，只有严格高分才拿得走，不能抢纯静态设计。"""
        for desc, want in [
            ("生成小红书风格封面海报，调整配色与视觉层次", "visual"),
            ("把文档一键转成幻灯片 deck 与演示大纲", "slides"),
            ("生成高美感前端 ui 设计原型，覆盖 ui/ux 规范", "figma"),
        ]:
            got, _c, why = scene.tag_scene_l2({"name": "x", "description": desc}, "design")
            self.assertEqual(want, got, f"{desc!r} 期望 {want}，实际 {got!r}（{why}）")


class TestSceneL2BiLabel(unittest.TestCase):
    """bi 桶改名。桶 id 不动，只改展示标签。"""

    def test_label_no_longer_promises_bi(self):
        # 语料实测：bi / 商业智能 / power bi / business intelligence 全部 0 命中，
        # 真实召回 100% 来自 指标 / dashboard / 报表。挂「BI」的徽标是空头承诺。
        self.assertEqual("指标看板", scene.SCENE_L2_LABELS["bi"])
        self.assertEqual("Metrics & Dashboards", scene.SCENE_L2_LABELS_EN["bi"])
        self.assertNotIn("BI", scene.SCENE_L2_LABELS["bi"])

    def test_bucket_id_kept_for_published_feed(self):
        """已发布的 feed.json 存着 scene_l2="bi"，feedback 权重也按这个 id 累计。
        改 id 会让历史数据对不上，所以 id 必须保持 bi。"""
        ids = [cid for cid, _l, _k in scene.SCENES_L2["data-review"]]
        self.assertIn("bi", ids)

    def test_metrics_content_still_lands_here(self):
        got, _c, why = scene.tag_scene_l2(
            {"name": "data-analysis",
             "description": "用 SQL 快速分析 Excel/CSV 数据，生成统计摘要和多格式报表"},
            "data-review")
        self.assertEqual("bi", got, why)


class TestPathSignalNotAuthoritative(unittest.TestCase):
    """路径/仓库名信号。这和上一轮「skill_path 含 skill 就判 agent-tooling」同源：
    拿路径当强信号覆盖内容判断。fixture 全部取自真实条目。
    """

    # 真实条目：Leonxlnx/taste-skill 仓库下 13 个 skill 命中 taste，
    # 这一个讲的是禁止 LLM 截断输出，跟设计毫无关系。字段照抄真实数据。
    FULL_OUTPUT = {
        "name": "full-output-enforcement",
        "full_name": "Leonxlnx/taste-skill",
        "skill_path": "skills/output-skill/SKILL.md",
        "description": "Overrides default LLM truncation behavior. Enforces complete "
                       "code generation, bans placeholder patterns, and handles "
                       "token-limit splits cleanly.",
        "one_liner_zh": "强制生成完整代码，不截断、不省略、不打省略号。",
        "who_for_zh": "需要确定性完整输出的开发者",
        "highlights_zh": ["彻底禁用 LLM 截断输出", "自动拦截所有占位符模式",
                          "智能分块输出超长内容"],
    }

    def test_repo_named_taste_does_not_force_design(self):
        got = scene.apply_scene(dict(self.FULL_OUTPUT))
        self.assertNotEqual(
            "design", got["scene"],
            f"仓库名 taste-skill 不该决定内容判定（{got['scene_why']}）")
        self.assertEqual("engineering", got["scene"], got["scene_why"])

    def test_full_name_does_not_decide_scene(self):
        """只有 full_name 不同的两条，判定必须一致——仓库名描述的是合集不是这个 skill。"""
        base = {k: v for k, v in self.FULL_OUTPUT.items() if k != "full_name"}
        a = scene.apply_scene(dict(base, full_name="Leonxlnx/taste-skill"))
        b = scene.apply_scene(dict(base, full_name="someone/random-tools"))
        self.assertEqual(a["scene"], b["scene"])
        self.assertEqual(a["scene_l2"], b["scene_l2"])

    def test_content_signal_beats_path_signal(self):
        """nexu-io/open-design 仓库下这三条本该归内容创作，不该被仓库名拽进设计。"""
        got = scene.apply_scene({
            "name": "card-xiaohongshu",
            "full_name": "nexu-io/open-design",
            "skill_path": "skills/card-xiaohongshu/SKILL.md",
            "description": "Xiaohongshu-style knowledge cards, arranged as a "
                           "swipeable multi-card carousel.",
            "one_liner_zh": "生成小红书风格的图文知识卡片轮播图",
        })
        self.assertEqual("content", got["scene"], got["scene_why"])
        self.assertEqual("social", got["scene_l2"], got["scene_l2_why"])

    def test_path_only_hit_is_not_overconfident(self):
        """路径信号可以把没有任何内容信号的纯设计目录救出 other，但不许再报 0.86：
        对一个只看了目录名的判断表现得那么自信，本身就是 bug。
        """
        got = scene.apply_scene({
            "name": "brand-guidelines",
            "full_name": "anthropics/skills",
            "skill_path": "skills/brand-guidelines/SKILL.md",
            "description": "",
        })
        self.assertEqual("design", got["scene"])
        self.assertIn("path:", got["scene_why"])
        self.assertLessEqual(
            got["scene_confidence"], 0.7,
            f"纯路径命中的置信度 {got['scene_confidence']} 太高了")

    def test_ui_suffix_in_skill_name_still_counts(self):
        """skill 自己的名字（不是仓库名）带 -ui 是可靠的设计信号：
        实测 4 条命中全是 UI 组件库/设计 skill，零污染。
        """
        got = scene.apply_scene({
            "name": "industrial-brutalist-ui",
            "full_name": "Leonxlnx/taste-skill",
            "skill_path": "skills/brutalist-skill/SKILL.md",
            "description": "Raw mechanical interfaces fusing Swiss typographic print "
                           "with military terminal aesthetics. For data-heavy "
                           "dashboards, portfolios, or editorial sites.",
            "one_liner_zh": "构建数据密集型仪表盘、作品集或编辑类网站，呈现解密蓝图般的机械终端视觉",
            "who_for_zh": "追求硬核功能美学的前端设计师",
        })
        # 正文里的 data-heavy dashboards 会让内容打分偏向「数据与复盘」，
        # 名字里的 -ui 才是真信号。
        self.assertEqual("design", got["scene"], got["scene_why"])

    def test_path_keys_carry_no_repo_branding(self):
        """路径词表里不许再出现纯仓库品牌名。open-design 就是这么进来的：
        它在 skill 目录名里一次都没出现过，只匹配 nexu-io/open-design 这个仓库。
        """
        self.assertNotIn("open-design", scene._PATH_DESIGN_KEYS)
        # prototype 是通用词，唯一的覆盖对象是 deploy-prototype（部署原型，实为工程）；
        # 作为内容关键词它已经在 RULES / SCENES_L2 里公平参与打分了。
        self.assertNotIn("prototype", scene._PATH_DESIGN_KEYS)
        self.assertIn("prototype", dict(scene.RULES)["design"])


class TestI18nCacheKey(unittest.TestCase):
    def test_same_repo_different_skills_do_not_collide(self):
        a = {"full_name": "anthropics/skills", "skill_path": "skills/pdf/SKILL.md"}
        b = {"full_name": "anthropics/skills", "skill_path": "skills/xlsx/SKILL.md"}
        self.assertNotEqual(i18n.cache_key(a), i18n.cache_key(b))

    def test_key_falls_back_to_full_name(self):
        self.assertEqual(i18n.cache_key({"full_name": "a/b"}), "a/b")

    def test_legacy_row_without_path_still_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            root = data / "i18n"
            root.mkdir(parents=True)
            (root / "cards.jsonl").write_text(
                '{"full_name":"a/b","hash":"h1","fields":{"one_liner_zh":"x"}}\n',
                encoding="utf-8",
            )
            cache = i18n.load_cache(data)
            self.assertIn("a/b", cache)


class TestPersonalRank(unittest.TestCase):
    def test_rerank_prefers_feedback_scene(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            (data / "feedback.jsonl").write_text(
                '{"action":"useful","scene":"content","scene_l2":"writing","full_name":"a/stop"}\n'
                '{"action":"opened_github","scene":"content","full_name":"a/stop"}\n'
                '{"action":"bad","scene":"quality","full_name":"b/bug"}\n',
                encoding="utf-8",
            )
            aff = rank.load_feedback_affinity(data)
            self.assertGreater(aff["scene_boost"].get("content", 0), 0)
            self.assertGreater(aff["repo_penalty"].get("b/bug", 0), 0)
            items = [
                {
                    "full_name": "b/bug",
                    "name": "bug",
                    "description": "debug testing qa",
                    "rel_score": 0.5,
                    "scene": "quality",
                    "scene_l2": "debug",
                    "stars": 100,
                    "source": "github-search",
                },
                {
                    "full_name": "a/stop",
                    "name": "stop-slop",
                    "description": "writing copy",
                    "rel_score": 0.4,
                    "scene": "content",
                    "scene_l2": "writing",
                    "stars": 10,
                    "source": "hellogithub",
                },
            ]
            ranked = rank.rerank(items, affinity=aff, intent="写作润色")
            self.assertEqual(ranked[0]["full_name"], "a/stop")
            self.assertIn("personal_score", ranked[0])


class TestGitHubSearch(unittest.TestCase):
    def test_repo_row(self):
        row = github_search._repo_row({
            "full_name": "acme/skills",
            "html_url": "https://github.com/acme/skills",
            "description": "agent skills",
            "language": "Python",
            "stargazers_count": 42,
            "score": 1.2,
        })
        self.assertEqual(row["source"], "github-search")
        self.assertEqual(row["stars"], 42)

    def test_fetch_uses_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            cache = data / "cache"
            cache.mkdir(parents=True)
            (cache / "github_search.json").write_text(
                '{"fetched_at":"2099-01-01T00:00:00+00:00","items":[{"full_name":"x/y","source":"github-search","stars":1,"url":"https://github.com/x/y","description":"d","language":"","stars_today":0,"kind":"skill"}],"meta":{}}',
                encoding="utf-8",
            )
            items, meta = github_search.fetch_search_candidates(
                data, user_agent="test", force=False, ttl_hours=24,
            )
            self.assertTrue(meta.get("from_cache"))
            self.assertEqual(items[0]["full_name"], "x/y")

    def test_search_repos_parses(self):
        fake = {
            "items": [{
                "full_name": "acme/agent-skills",
                "html_url": "https://github.com/acme/agent-skills",
                "description": "Claude skills",
                "language": "MD",
                "stargazers_count": 99,
                "score": 10,
            }],
        }
        with mock.patch.object(github_search, "_http_json", return_value=(200, fake, {})):
            rows, meta = github_search.search_repos("ua", token="", queries=['"SKILL.md" in:readme'], sleep_s=0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["full_name"], "acme/agent-skills")
        self.assertEqual(meta["returned"], 1)


class TestFeedUI(unittest.TestCase):
    def test_l2_and_search_labels(self):
        feed = {
            "meta": {},
            "scenes": scene.scene_chips(),
            "scenes_l2": scene.scene_l2_tree(),
            "items": [{
                "full_name": "a/b",
                "name": "b",
                "description": "desc long enough",
                "source": "github-search",
                "scene": "content",
                "scene_label": "内容创作",
                "scene_l2": "writing",
                "scene_l2_label": "写作润色",
                "personal_score": 0.55,
                "rank_why": "rel:0.4 · intent:写作",
                "kind": "skill",
                "url": "https://github.com/a/b",
            }],
            "corpus": [],
        }
        html = feed_dashboard.build_feed_html(feed)
        self.assertIn("二级场景", html)
        self.assertIn("GitHub Search", html)
        self.assertIn("写作润色", html)
        self.assertIn("personal_score", html)
        self.assertNotIn("/api/install", html)


if __name__ == "__main__":
    unittest.main()
