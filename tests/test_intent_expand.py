"""意图近义扩展：短口语 → 语料真实 token（前后端同源）。"""

from __future__ import annotations

import unittest

import geo
import intent_expand


class TestIntentExpand(unittest.TestCase):
    def test_imagen_expands_visual_tokens(self):
        terms = intent_expand.expand_terms("生图")
        for need in ("生图", "海报", "canvas-design", "视觉海报", "配图", "出图"):
            self.assertIn(need, terms, need)

    def test_aliases_share_cluster(self):
        a = intent_expand.expand_terms("画图")
        b = intent_expand.expand_terms("image-gen")
        self.assertIn("canvas-design", a)
        self.assertIn("canvas-design", b)
        self.assertTrue({"生图", "海报"} <= a)

    def test_unrelated_query_stays_narrow(self):
        terms = intent_expand.expand_terms("周报")
        self.assertNotIn("canvas-design", terms)
        self.assertNotIn("海报", terms)

    def test_score_blob_ranks_visual_over_unrelated(self):
        visual = "canvas-design create beautiful visual art 视觉海报 海报"
        api = "rest api openapi sdk typescript"
        self.assertGreater(
            intent_expand.score_blob(visual, "生图"),
            intent_expand.score_blob(api, "生图"),
        )
        self.assertEqual(intent_expand.score_blob(api, "生图"), 0.0)

    def test_geo_search_items_uses_expansion(self):
        items = geo.sanitize_items([
            {
                "full_name": "anthropics/skills",
                "name": "canvas-design",
                "description": "Create beautiful visual art",
                "url": "https://github.com/anthropics/skills",
                "stars": 100,
                "scene": "design",
                "scene_label": "设计与视觉",
                "scene_l2": "visual",
                "scene_l2_label": "视觉海报",
            },
            {
                "full_name": "acme/rest-kit",
                "name": "rest-kit",
                "description": "OpenAPI REST helpers",
                "url": "https://github.com/acme/rest-kit",
                "stars": 200,
                "scene": "engineering",
                "scene_label": "工程开发",
                "scene_l2": "sdk",
                "scene_l2_label": "SDK/API",
            },
        ])
        page, total = geo.search_items(items, query="生图", limit=5)
        self.assertEqual(total, 1)
        self.assertEqual(page[0]["full_name"], "anthropics/skills")


if __name__ == "__main__":
    unittest.main()
