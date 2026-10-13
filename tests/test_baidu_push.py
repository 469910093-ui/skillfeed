"""百度每日推送：挑页顺序、记账、额度与失败要喊出来。"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import baidu_push as bp

S = bp.SITE
SITEMAP = f"""<?xml version="1.0"?><urlset>
<url><loc>{S}/s/acme-a.html</loc></url>
<url><loc>{S}/scene/content.html</loc></url>
<url><loc>{S}/</loc></url>
<url><loc>{S}/s/acme-b.html</loc></url>
<url><loc>{S}/faq.html</loc></url>
<url><loc>https://evil.example/x.html</loc></url>
<url><loc>{S}/faq.html</loc></url>
</urlset>"""


class TestPickBatch(unittest.TestCase):
    def setUp(self):
        self.urls = bp.parse_sitemap(SITEMAP)

    def test_sitemap_keeps_own_site_and_dedupes(self):
        self.assertEqual(5, len(self.urls))
        self.assertNotIn("https://evil.example/x.html", self.urls)

    def test_top_pages_then_scenes_then_details(self):
        self.assertEqual(
            [f"{S}/", f"{S}/faq.html", f"{S}/scene/content.html", f"{S}/s/acme-a.html"],
            bp.pick_batch(self.urls, {}, 4))

    def test_unpushed_first_then_oldest_pushed(self):
        pushed = {f"{S}/": "2026-10-13", f"{S}/faq.html": "2026-10-10",
                  f"{S}/scene/content.html": "2026-10-12"}
        self.assertEqual(
            [f"{S}/s/acme-a.html", f"{S}/s/acme-b.html", f"{S}/faq.html", f"{S}/scene/content.html"],
            bp.pick_batch(self.urls, pushed, 4))


class TestMain(unittest.TestCase):
    def run_main(self, *, push_result=None, token="t", extra=()):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        state = Path(tmp.name) / "state.json"
        env = {"BAIDU_PUSH_TOKEN": token, "BAIDU_PUSH_MARK": "", "GITHUB_STEP_SUMMARY": ""}
        with mock.patch.dict("os.environ", env), \
                mock.patch.object(bp, "fetch_sitemap", return_value=SITEMAP), \
                mock.patch.object(bp, "push", return_value=push_result) as p:
            code = bp.main(["--state", str(state), *extra])
        return code, bp.load_state(state), p

    def test_success_records_pushed_and_learns_quota(self):
        code, state, p = self.run_main(push_result=(200, {"success": 2, "remain": 8}))
        self.assertEqual(0, code)
        self.assertEqual(5, len(p.call_args.args[0]))
        self.assertEqual(2, len(state["pushed"]))
        self.assertEqual(10, state["quota"])

    def test_over_quota_is_a_warning_not_a_failure(self):
        code, state, _ = self.run_main(push_result=(400, {"error": 400, "message": "over quota"}))
        self.assertEqual(0, code)
        self.assertEqual({}, state["pushed"])

    def test_bad_token_fails_loudly(self):
        code, _, _ = self.run_main(push_result=(401, {"error": 401, "message": "token is not valid"}))
        self.assertEqual(1, code)

    def test_missing_token_fails(self):
        code, _, p = self.run_main(token="")
        self.assertEqual(1, code)
        p.assert_not_called()

    def test_mark_only_records_without_calling_baidu(self):
        code, state, p = self.run_main(extra=("--mark", f"{S}/", "https://evil.example/"))
        self.assertEqual(0, code)
        p.assert_not_called()
        self.assertEqual([f"{S}/"], list(state["pushed"]))


if __name__ == "__main__":
    unittest.main()
