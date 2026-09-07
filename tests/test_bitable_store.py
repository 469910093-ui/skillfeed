import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bitable_store as bs
import i18n

FIELDS = {
    "one_liner_zh": "一键洗掉 AI 腔，让文字像人写的",
    "one_liner_en": "Remove AI tells so prose reads human.",
    "highlights_zh": ["删除空洞套话", "打破刻板句式", "强制主动语态"],
    "highlights_en": ["Cuts filler", "Breaks rigid patterns", "Enforces active voice"],
    "who_for_zh": "编辑、作者",
    "who_for_en": "Editors, writers",
}

ITEM = {
    "full_name": "hardikpandya/stop-slop",
    "skill_path": "SKILL.md",
    "name": "stop-slop",
    "description": "A skill file for removing AI tells from prose",
    "url": "https://github.com/hardikpandya/stop-slop",
}


class TestRecordRoundTrip(unittest.TestCase):
    def test_to_record_then_back(self):
        rec = bs._to_record(
            ITEM, FIELDS, hash_="abc123", model="qwen-plus", status=bs.STATUS_PENDING
        )
        self.assertEqual(rec["唯一键"], "hardikpandya/stop-slop#SKILL.md")
        self.assertEqual(rec["亮点_中"].count("\n"), 2)

        back = bs._from_record({"record_id": "recX", **rec})
        self.assertIsNotNone(back)
        self.assertEqual(back["fields"]["one_liner_zh"], FIELDS["one_liner_zh"])
        self.assertEqual(back["fields"]["highlights_zh"], FIELDS["highlights_zh"])
        self.assertEqual(back["hash"], "abc123")
        self.assertEqual(back["record_id"], "recX")
        self.assertFalse(back["locked"])

    def test_accepted_row_is_locked(self):
        rec = bs._to_record(
            ITEM, FIELDS, hash_="h", model="m", status=bs.STATUS_ACCEPTED
        )
        back = bs._from_record({"record_id": "recY", **rec})
        self.assertTrue(back["locked"])

    def test_select_cell_read_as_array(self):
        """单选字段读回来是 ['已验收']，不能当成字符串处理。"""
        rec = bs._to_record(ITEM, FIELDS, hash_="h", model="m", status="x")
        rec["状态"] = [bs.STATUS_ACCEPTED]
        back = bs._from_record({"record_id": "r", **rec})
        self.assertEqual(back["status"], bs.STATUS_ACCEPTED)
        self.assertTrue(back["locked"])

    def test_rich_text_cell(self):
        self.assertEqual(bs._cell_text([{"text": "甲"}, {"text": "乙"}]), "甲乙")
        self.assertEqual(bs._cell_text(None), "")

    def test_incomplete_row_rejected(self):
        """字段不全的行不能进缓存，否则前端会拿到半截译稿。"""
        rec = bs._to_record(ITEM, FIELDS, hash_="h", model="m", status="待审")
        rec["一句话_中"] = ""
        self.assertIsNone(bs._from_record({"record_id": "r", **rec}))

    def test_writable_wraps_select(self):
        out = bs._writable({"状态": bs.STATUS_ACCEPTED, "名称": "x"})
        self.assertEqual(out["状态"], [bs.STATUS_ACCEPTED])
        self.assertEqual(out["名称"], "x")


class TestLockedSkipsTranslation(unittest.TestCase):
    def test_locked_row_survives_content_change(self):
        """已验收的行，即使上游内容变了也不重译——这是省 token 的核心。"""
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            root = data / "i18n"
            root.mkdir(parents=True)
            (root / "cards.jsonl").write_text(
                json.dumps(
                    {
                        "full_name": ITEM["full_name"],
                        "skill_path": ITEM["skill_path"],
                        "hash": "STALE",
                        "locked": True,
                        "fields": FIELDS,
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            item = dict(ITEM, description="描述已经改过了，指纹必然不一样")
            stats = i18n.enrich_items(data, [item], api_key="")
            self.assertEqual(stats["locked"], 1)
            self.assertEqual(stats["translated"], 0)
            self.assertEqual(stats["skipped"], 0)
            self.assertEqual(item["one_liner_zh"], FIELDS["one_liner_zh"])

    def test_unlocked_stale_row_would_retranslate(self):
        """没验收的行指纹不符就该重译（无 key 时记为 skipped）。"""
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp)
            root = data / "i18n"
            root.mkdir(parents=True)
            (root / "cards.jsonl").write_text(
                json.dumps(
                    {
                        "full_name": ITEM["full_name"],
                        "skill_path": ITEM["skill_path"],
                        "hash": "STALE",
                        "fields": FIELDS,
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            item = dict(ITEM, description="改过了")
            stats = i18n.enrich_items(data, [item], api_key="")
            self.assertEqual(stats["locked"], 0)
            self.assertEqual(stats["cached"], 0)
            self.assertEqual(stats["skipped"], 1)


class FakeCli:
    """假 lark-cli：按预设分页返回，同时记下每次调用的 offset/limit/输出文件名。

    resp_builder 用来伪造 --minimal-stdout 那段 JSON，好覆盖 has_more 缺失、
    records_count 与实际行数不一致之类的异常响应。
    """

    def __init__(self, pages, *, resp_builder=None):
        self.pages = pages
        self.resp_builder = resp_builder
        self.calls: list[dict] = []
        self.files: dict[str, list[dict]] = {}

    def run_lark(self, args, *, cwd=None):
        opts = {a: args[i + 1] for i, a in enumerate(args) if a.startswith("--")}
        idx = len(self.calls)
        self.calls.append(
            {
                "offset": int(opts["--offset"]),
                "limit": int(opts["--limit"]),
                "output": opts["--output"],
            }
        )
        rows = self.pages[idx] if idx < len(self.pages) else []
        out = opts["--output"]
        if out in self.files:
            raise AssertionError(f"输出文件名重复，前一页会被 --overwrite 冲掉: {out}")
        self.files[out] = rows
        if self.resp_builder:
            return self.resp_builder(idx, rows)
        return {"records_count": len(rows), "has_more": idx < len(self.pages) - 1}

    def read_ndjson(self, path):
        return list(self.files.get(Path(path).name, []))


def _cheap_rows(start, n):
    """_list_records 不看字段内容，翻页测试用最省的记录就够。"""
    return [{"record_id": f"rec{i}"} for i in range(start, start + n)]


class _PagingCase(unittest.TestCase):
    def _run(self, pages, *, resp_builder=None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        data = Path(tmp.name)
        bs.save_target(data, "bascnFAKE", "tblFAKE")
        cli = FakeCli(pages, resp_builder=resp_builder)
        with mock.patch.object(bs, "run_lark", cli.run_lark), mock.patch.object(
            bs, "_read_ndjson", cli.read_ndjson
        ):
            try:
                return cli, bs._list_records(data), None
            except RuntimeError as exc:
                return cli, None, exc

    def _pull(self, pages):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        data = Path(tmp.name)
        bs.save_target(data, "bascnFAKE", "tblFAKE")
        cli = FakeCli(pages)
        with mock.patch.object(bs, "run_lark", cli.run_lark), mock.patch.object(
            bs, "_read_ndjson", cli.read_ndjson
        ):
            return data, bs.pull(data)


class TestListRecordsPaging(_PagingCase):
    def test_collects_every_page(self):
        """超过单页上限 2000 条时必须接着翻，不能只拿第一页。"""
        pages = [
            _cheap_rows(0, bs.PAGE_LIMIT),
            _cheap_rows(bs.PAGE_LIMIT, bs.PAGE_LIMIT),
            _cheap_rows(bs.PAGE_LIMIT * 2, 383),
        ]
        cli, got, err = self._run(pages)
        self.assertIsNone(err)
        self.assertEqual(len(got), bs.PAGE_LIMIT * 2 + 383)
        ids = [r["record_id"] for r in got]
        self.assertEqual(len(set(ids)), len(ids), "翻页不应重复取同一条")
        self.assertEqual(ids[0], "rec0")
        self.assertEqual(ids[-1], f"rec{bs.PAGE_LIMIT * 2 + 382}")

    def test_offset_advances_by_records_count(self):
        pages = [_cheap_rows(0, bs.PAGE_LIMIT), _cheap_rows(bs.PAGE_LIMIT, 5)]
        cli, got, err = self._run(pages)
        self.assertIsNone(err)
        self.assertEqual([c["offset"] for c in cli.calls], [0, bs.PAGE_LIMIT])
        self.assertEqual({c["limit"] for c in cli.calls}, {bs.PAGE_LIMIT})

    def test_each_page_gets_its_own_file(self):
        """共用一个输出名会被 --overwrite 冲掉，FakeCli 里直接断言重名。"""
        cli, got, err = self._run([_cheap_rows(0, 3), _cheap_rows(3, 3), _cheap_rows(6, 1)])
        self.assertIsNone(err)
        names = [c["output"] for c in cli.calls]
        self.assertEqual(len(set(names)), 3)
        self.assertEqual(len(got), 7)

    def test_single_page_makes_one_call(self):
        cli, got, err = self._run([_cheap_rows(0, 12)])
        self.assertIsNone(err)
        self.assertEqual(len(cli.calls), 1)
        self.assertEqual(len(got), 12)

    def test_bad_line_does_not_shift_offset(self):
        """有行解析失败时按 records_count 推进，否则 offset 错位会漏记录。"""
        pages = [_cheap_rows(0, 1998), _cheap_rows(bs.PAGE_LIMIT, 4)]

        def resp(idx, rows):
            # 第一页服务端给了 2000 条，但 ndjson 里有 2 行坏掉被跳过。
            if idx == 0:
                return {"records_count": bs.PAGE_LIMIT, "has_more": True}
            return {"records_count": len(rows), "has_more": False}

        cli, got, err = self._run(pages, resp_builder=resp)
        self.assertIsNone(err)
        self.assertEqual([c["offset"] for c in cli.calls], [0, bs.PAGE_LIMIT])


class TestListRecordsFailsLoud(_PagingCase):
    """静默截断是这个 bug 的本质，任何取不完的情况都必须抛错而不是返回半张表。"""

    def test_missing_has_more_raises(self):
        cli, got, err = self._run(
            [_cheap_rows(0, 10)],
            resp_builder=lambda idx, rows: {"records_count": len(rows)},
        )
        self.assertIsNone(got)
        self.assertIn("has_more", str(err))

    def test_unparseable_stdout_raises(self):
        cli, got, err = self._run(
            [_cheap_rows(0, 10)],
            resp_builder=lambda idx, rows: {"_raw": "some human text"},
        )
        self.assertIsNone(got)
        self.assertIn("has_more", str(err))

    def test_has_more_with_empty_page_raises(self):
        cli, got, err = self._run(
            [_cheap_rows(0, 5), []],
            resp_builder=lambda idx, rows: {"records_count": len(rows), "has_more": True},
        )
        self.assertIsNone(got)
        self.assertEqual(len(cli.calls), 2, "空页应立刻中止，不再继续翻")
        self.assertIn("0 条", str(err))

    def test_runaway_has_more_is_bounded(self):
        """CLI 永远说还有下一页时要撞上页数上限退出，不能死循环。"""
        cli, got, err = self._run(
            [_cheap_rows(i * 10, 10) for i in range(bs.MAX_PAGES + 20)],
            resp_builder=lambda idx, rows: {"records_count": len(rows), "has_more": True},
        )
        self.assertIsNone(got)
        self.assertEqual(len(cli.calls), bs.MAX_PAGES)
        self.assertIn("MAX_PAGES", str(err))


class TestPullReachesLastPage(_PagingCase):
    def test_accepted_row_on_later_page_gets_locked(self):
        """第二页上的「已验收」行必须进缓存并打 locked，否则下次 i18n 会重译覆盖。"""
        def rec(i, status):
            item = {
                "full_name": f"owner/repo{i}",
                "skill_path": "SKILL.md",
                "name": f"s{i}",
                "url": f"https://github.com/owner/repo{i}",
            }
            body = bs._to_record(item, FIELDS, hash_=f"h{i}", model="m", status=status)
            return {"record_id": f"rec{i}", **body}

        with mock.patch.object(bs, "PAGE_LIMIT", 2):
            data, stats = self._pull(
                [
                    [rec(0, bs.STATUS_PENDING), rec(1, bs.STATUS_PENDING)],
                    [rec(2, bs.STATUS_ACCEPTED)],
                ]
            )

        self.assertEqual(stats["remote"], 3)
        self.assertEqual(stats["accepted"], 1)
        cache = i18n.load_cache(data)
        self.assertIn("owner/repo2#SKILL.md", cache)
        self.assertTrue(cache["owner/repo2#SKILL.md"]["locked"])

        # 上游内容改了也不该重译——这是「已验收永不重译」的端到端证据。
        item = {
            "full_name": "owner/repo2",
            "skill_path": "SKILL.md",
            "name": "s2",
            "description": "内容改过了，指纹必然不同",
        }
        got = i18n.enrich_items(data, [item], api_key="")
        self.assertEqual(got["locked"], 1)
        self.assertEqual(got["translated"], 0)


if __name__ == "__main__":
    unittest.main()
