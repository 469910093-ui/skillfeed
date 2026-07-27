import unittest
from pathlib import Path

import trending

FIX = Path(__file__).resolve().parent / "fixtures" / "trending_sample.html"


class TestTrendingParse(unittest.TestCase):
    def test_parse_sample(self):
        html = FIX.read_text(encoding="utf-8")
        repos = trending.parse_trending_html(html)
        self.assertEqual(len(repos), 3)
        self.assertEqual(repos[0].full_name, "acme/agent-skills")
        self.assertIn("SKILL.md", repos[0].description)
        self.assertEqual(repos[0].language, "Python")
        self.assertEqual(repos[0].stars, 1234)
        self.assertEqual(repos[0].stars_today, 56)
        self.assertEqual(repos[0].source, "github.com/trending")
        self.assertEqual(repos[1].full_name, "foo/bar-cli")
        self.assertEqual(repos[2].stars, 88)

    def test_trending_url(self):
        self.assertEqual(trending.trending_url("daily"), "https://github.com/trending")
        self.assertEqual(
            trending.trending_url("weekly"),
            "https://github.com/trending?since=weekly",
        )


if __name__ == "__main__":
    unittest.main()
