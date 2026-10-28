"""统一检索：全文 md（多语种）+ 场景推断。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import md_store
import skill_search


def _item(full_name, name, desc, scene="other", scene_l2="", path=""):
    return {
        "full_name": full_name,
        "name": name,
        "description": desc,
        "url": f"https://github.com/{full_name}",
        "stars": 100,
        "scene": scene,
        "scene_l2": scene_l2,
        "skill_path": path,
    }


WEEKLY = _item("acme/retro", "retro", "Weekly retrospective and status report writer",
               scene="data-review", scene_l2="weekly")
DIAGRAM = _item("acme/arch-draw", "arch-draw", "Draw architecture diagrams with mermaid",
                scene="design", scene_l2="chart")
REFACTOR = _item("acme/refactor", "refactor", "Refactor legacy architecture code",
                 scene="engineering")
OPAQUE = _item("acme/opaque", "opaque", "General helper", path="skills/opaque/SKILL.md")


class TestUnderstand(unittest.TestCase):
    def test_weekly_infers_scene_across_languages(self):
        for q in ("周报", "weekly report", "週報"):
            u = skill_search.understand(q)
            self.assertIn("weekly", u.scenes_l2, q)

    def test_diagram_not_pulled_to_engineering(self):
        u = skill_search.understand("画架构图")
        self.assertIn("chart", u.scenes_l2)
        self.assertNotIn("engineering", u.scenes)


class TestSearch(unittest.TestCase):
    def test_cross_lingual_same_top(self):
        pool = [REFACTOR, WEEKLY, DIAGRAM]
        zh = skill_search.search(pool, "周报")
        en = skill_search.search(pool, "weekly report")
        self.assertEqual(zh[0].item["full_name"], "acme/retro")
        self.assertEqual(en[0].item["full_name"], "acme/retro")

    def test_diagram_ranks_over_refactor(self):
        hits = skill_search.search([REFACTOR, DIAGRAM], "画架构图")
        self.assertEqual(hits[0].item["full_name"], "acme/arch-draw")

    def test_md_body_hit_via_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            md_store.save_md(root, OPAQUE, "# Opaque\n\n生成海报和插图，poster generator.")
            lookup = md_store.MdLookup(root)
            self.assertEqual(skill_search.search([OPAQUE], "海报"), [])
            hits = skill_search.search([OPAQUE], "海报", md_lookup=lookup)
            self.assertEqual(len(hits), 1)
            self.assertGreater(hits[0].rel, 0)

    def test_dedupes_same_skill(self):
        hits = skill_search.search([WEEKLY, dict(WEEKLY)], "周报")
        self.assertEqual(len(hits), 1)


if __name__ == "__main__":
    unittest.main()
