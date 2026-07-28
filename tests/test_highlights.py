import unittest

import highlights


class TestHighlights(unittest.TestCase):
    def test_extract_problem_and_bullets(self):
        body = """# Brainstorming

Help turn ideas into designs.

## Core Rules
1. Ask questions one at a time
2. Present design before coding
- Cut filler phrases from prose
"""
        out = highlights.extract_highlights(
            body,
            "You MUST use this before creative work to explore intent.",
        )
        self.assertIn("creative work", out["problem"].lower())
        self.assertGreaterEqual(len(out["highlights"]), 2)
        self.assertTrue(any("Ask questions" in h or "design" in h.lower() for h in out["highlights"]))

    def test_fallback_without_body(self):
        out = highlights.extract_highlights("", "去掉 AI 味写作技能包，润色文案减少套话")
        self.assertTrue(out["problem"])
        self.assertTrue(out["highlights"])


if __name__ == "__main__":
    unittest.main()
