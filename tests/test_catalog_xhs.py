"""catalog + xiaohongshu 源单元测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import catalog_sources
import gates
import xiaohongshu


class CatalogSourcesTest(unittest.TestCase):
    def test_extract_github_names(self):
        text = """
        - [foo](https://github.com/anthropics/skills)
        - https://github.com/vercel-labs/agent-skills/tree/main/skills/x
        - ignore https://github.com/topics/agent-skills
        """
        names = catalog_sources.extract_github_full_names(text)
        self.assertIn("anthropics/skills", names)
        self.assertIn("vercel-labs/agent-skills", names)
        self.assertNotIn("topics/agent-skills", [n.lower() for n in names])


class XiaohongshuTest(unittest.TestCase):
    def test_seed_and_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            data_dir = Path(td)
            payload = xiaohongshu.ensure_seed_mentions(data_dir)
            self.assertGreaterEqual(len(payload.get("repos") or []), 5)
            rows, meta = xiaohongshu.candidates_from_mentions(data_dir, max_repos=10)
            self.assertTrue(rows)
            self.assertEqual(rows[0]["source"], "xiaohongshu")
            self.assertIn("github.com", rows[0]["url"])
            self.assertGreaterEqual(meta["returned"], 1)

    def test_extract_repos_from_note(self):
        text = "推荐这个 https://github.com/hardikpandya/stop-slop 去 AI 味 skill"
        repos = xiaohongshu.extract_repos_from_text(text)
        self.assertEqual(repos, ["hardikpandya/stop-slop"])


class GatesAllowNewSources(unittest.TestCase):
    def test_defaults_include_catalog_xhs(self):
        self.assertIn("catalog", gates.DEFAULT_ALLOWED_SOURCES)
        self.assertIn("xiaohongshu", gates.DEFAULT_ALLOWED_SOURCES)


if __name__ == "__main__":
    unittest.main()
