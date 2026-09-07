"""设计类 skill 路径优先级与展开。"""

from __future__ import annotations

import unittest

import skill_detect


class PathPriorityTest(unittest.TestCase):
    def test_frontend_design_beats_algorithmic_art(self):
        paths = [
            "skills/algorithmic-art/SKILL.md",
            "skills/frontend-design/SKILL.md",
            "skills/webapp-testing/SKILL.md",
        ]
        ordered = sorted(paths, key=skill_detect.path_priority)
        self.assertEqual(ordered[0], "skills/frontend-design/SKILL.md")

    def test_item_id_distinguishes_skills(self):
        a = skill_detect.skill_item_id("anthropics/skills", "skills/frontend-design/SKILL.md")
        b = skill_detect.skill_item_id("anthropics/skills", "skills/algorithmic-art/SKILL.md")
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith("anthropics/skills::"))


class CatalogForceProbeTest(unittest.TestCase):
    def test_design_seeds_present(self):
        import catalog_sources

        seeds = set(catalog_sources.DEFAULT_SEED_REPOS)
        force = set(catalog_sources.FORCE_PROBE_REPOS)
        for name in (
            "xiaopu-ai/web-design",
            "Ilm-Alan/frontend-design",
            "Leonxlnx/taste-skill",
            "nexu-io/open-design",
            "anthropics/skills",
        ):
            self.assertIn(name, seeds)
            self.assertIn(name, force)


if __name__ == "__main__":
    unittest.main()
