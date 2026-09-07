"""排序核心：CTR 去偏、多样性、探索位、会话稳定性、搜索优先级。

全部走纯函数，不碰网络/数据库/文件；时间一律显式传 now，不 sleep。
"""

import unittest
from datetime import datetime, timedelta, timezone

import ranking

NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=timezone.utc)
CFG = ranking.resolve_config(None)


def item(key, *, scene="engineering", l2="infra", owner="acme", stars=100, **kw):
    row = {
        "id": key,
        "full_name": f"{owner}/{key}",
        "name": key,
        "description": kw.pop("description", f"{key} skill for agents"),
        "scene": scene,
        "scene_l2": l2,
        "owner": owner,
        "stars": stars,
        "first_seen_at": (NOW - timedelta(days=30)).isoformat(),
    }
    row.update(kw)
    return row


def stats(imps, clicks, band=1):
    return ranking.ItemStats(impressions={band: imps}, clicks={band: clicks})


class TestConfig(unittest.TestCase):
    def test_missing_keys_fall_back_to_defaults(self):
        """配置缺字段不能崩——线上 config.json 只写了一半是常态。"""
        cfg = ranking.resolve_config({"ranking": {"weights": {"focus": 0.9}}})
        self.assertEqual(cfg["weights"]["focus"], 0.9)
        self.assertEqual(cfg["weights"]["global_min"], 0.55)
        self.assertEqual(cfg["exploration"]["slots"], [5, 12, 17])

    def test_none_config_is_valid(self):
        self.assertEqual(ranking.resolve_config(None)["ctr"]["prior_alpha"], 20.0)


class TestWilsonAndCTR(unittest.TestCase):
    def test_low_exposure_cannot_beat_proven_item(self):
        """曝光 3 次点 2 次不能压过曝光 500 次点 60 次。"""
        gs = ranking.GlobalStats(ctr_overall=0.08, ctr_by_band={1: 0.08})
        lucky = ranking.ctr_ratio(item("lucky"), stats(3, 2), gs, CFG)
        proven = ranking.ctr_ratio(item("proven"), stats(500, 60), gs, CFG)
        self.assertLess(lucky, proven)
        # 而且被压到接近平均，不是维持在 66% / 8% = 8.3 倍
        self.assertLess(lucky, 1.15)

    def test_proven_bad_item_is_pushed_down(self):
        gs = ranking.GlobalStats(ctr_overall=0.08, ctr_by_band={1: 0.08})
        bad = ranking.ctr_ratio(item("bad"), stats(500, 10), gs, CFG)
        self.assertLess(bad, 0.5)

    def test_zero_impression_is_neutral(self):
        """0 曝光返回中性 1.0，不奖不罚；否则新条目永远出不来。"""
        gs = ranking.GlobalStats(ctr_overall=0.08, ctr_by_band={1: 0.08})
        self.assertEqual(ranking.ctr_ratio(item("fresh"), None, gs, CFG), 1.0)
        self.assertEqual(
            ranking.ctr_ratio(item("fresh"), ranking.ItemStats(), gs, CFG), 1.0,
        )

    def test_no_cliff_between_zero_and_one_impression(self):
        """0 曝光和 1 曝光之间不能有悬崖，否则「从没被展示过」反而成了优势。"""
        gs = ranking.GlobalStats(ctr_overall=0.08, ctr_by_band={1: 0.08})
        zero = ranking.ctr_ratio(item("a"), None, gs, CFG)
        one = ranking.ctr_ratio(item("b"), stats(1, 0), gs, CFG)
        self.assertLess(abs(zero - one), 0.2)

    def test_position_debias(self):
        """同样的点击数，长期占据头部位置的条目应当拿到更低的相对评价。"""
        gs = ranking.GlobalStats(
            ctr_overall=0.08, ctr_by_band={0: 0.20, 3: 0.02},
        )
        top = ranking.ItemStats(impressions={0: 200}, clicks={0: 20})
        deep = ranking.ItemStats(impressions={3: 200}, clicks={3: 20})
        self.assertLess(
            ranking.ctr_ratio(item("top"), top, gs, CFG),
            ranking.ctr_ratio(item("deep"), deep, gs, CFG),
        )

    def test_wilson_bounds(self):
        self.assertEqual(ranking.wilson_lower(0, 0), 0.0)
        self.assertGreater(ranking.wilson_lower(50, 100), 0.35)
        self.assertLess(ranking.wilson_lower(50, 100), 0.5)


class TestGlobalQuality(unittest.TestCase):
    def test_velocity_beats_stale_stock(self):
        """star 存量高但不涨的老项目，不该压过增速快的新项目。"""
        stale = item("stale", stars=50000, first_seen_at=(NOW - timedelta(days=400)).isoformat())
        rising = item("rising", stars=800, stars_today=300,
                      first_seen_at=(NOW - timedelta(days=5)).isoformat())
        g_stale, _ = ranking.global_quality(stale, config=CFG, now=NOW)
        g_rising, _ = ranking.global_quality(rising, config=CFG, now=NOW)
        self.assertGreater(g_rising, g_stale)

    def test_baked_velocity_is_reused(self):
        """线上 server 没有 star 快照文件，只能吃 feed.json 里烘焙好的增速。"""
        gain, conf = ranking.velocity_parts({"star_velocity": 42.0})
        self.assertEqual(gain, 42.0)
        self.assertGreater(conf, 0.5)

    def test_new_item_gets_neutral_ctr(self):
        fresh = item("fresh", first_seen_at=(NOW - timedelta(days=1)).isoformat())
        self.assertTrue(ranking.is_new_item(fresh, stats(5, 0), CFG, NOW))
        gs = ranking.GlobalStats(ctr_overall=0.08, ctr_by_band={1: 0.08})
        g_new, why = ranking.global_quality(
            fresh, stats=stats(5, 0), gstats=gs, config=CFG, now=NOW,
        )
        g_same_but_old, _ = ranking.global_quality(
            item("old", first_seen_at=(NOW - timedelta(days=1)).isoformat()),
            stats=stats(5, 0), gstats=gs, config=CFG, now=NOW,
        )
        self.assertIn("new", why)
        self.assertGreaterEqual(g_new, g_same_but_old)

    def test_grace_expires(self):
        old = item("old", first_seen_at=(NOW - timedelta(days=10)).isoformat())
        self.assertFalse(ranking.is_new_item(old, stats(5, 0), CFG, NOW))

    def test_heavily_exposed_item_leaves_grace(self):
        fresh = item("fresh", first_seen_at=(NOW - timedelta(days=1)).isoformat())
        self.assertFalse(ranking.is_new_item(fresh, stats(5000, 1), CFG, NOW))


class TestMonorepoStarInheritance(unittest.TestCase):
    """monorepo 拆出的子 skill 共享母仓库星数，star 是仓库级信号不是单条成绩。"""

    def _monorepo(self, n=20, stars=245604):
        return [
            item(f"sub{k}", owner="mattpocock", scene=f"s{k % 3}",
                 l2=f"l{k % 5}", stars=stars)
            for k in range(n)
        ]

    def _mono_fixed_name(self, n=20, stars=245604):
        rows = self._monorepo(n, stars)
        for r in rows:  # 同一个仓库拆出来的，full_name 相同
            r["full_name"] = "mattpocock/skills"
        return rows

    def test_share_shrinks_with_sibling_count(self):
        rows = self._mono_fixed_name(20)
        ranking.annotate_repo_share(rows, config=CFG)
        self.assertEqual(rows[0]["repo_items"], 20)
        self.assertAlmostEqual(rows[0]["_star_share"], 20 ** -0.5, places=4)

        solo = [item("only", owner="tiny", stars=300)]
        ranking.annotate_repo_share(solo, config=CFG)
        self.assertEqual(solo[0]["_star_share"], 1.0)

    def test_inherited_stars_lose_their_free_pass(self):
        """17 万星印在每个子 skill 上，不该让它们集体压过同样星数的独立仓库。"""
        rows = self._mono_fixed_name(20, stars=245604)
        solo = item("standalone", owner="indie", scene="research",
                    l2="wiki", stars=245604)
        solo["full_name"] = "indie/standalone"
        # 掺入普通仓库，让中性值落在中段——全是巨星仓时曲线已饱和，收缩无从体现
        filler = []
        for k in range(6):
            f = item(f"mid{k}", owner=f"m{k}", stars=800 + k * 100)
            f["full_name"] = f"m{k}/mid{k}"
            filler.append(f)
        ranking.annotate_repo_share(rows + [solo] + filler, config=CFG)
        mono_stock = ranking.shrink_to_neutral(
            ranking.raw_stock(rows[0]), rows[0]["_stock_neutral"], rows[0]["_star_share"])
        solo_stock = ranking.shrink_to_neutral(
            ranking.raw_stock(solo), solo["_stock_neutral"], solo["_star_share"])
        self.assertLess(mono_stock, solo_stock)

    def test_monorepo_cannot_own_the_first_screen(self):
        rows = self._mono_fixed_name(20)
        others = [
            item(f"indie{k}", owner=f"dev{k}", scene=f"t{k % 4}",
                 l2=f"m{k}", stars=400 + k * 50)
            for k in range(20)
        ]
        for k, r in enumerate(others):
            r["full_name"] = f"dev{k}/indie{k}"
        out = ranking.rank_feed(rows + others, config=CFG,
                                session_seed="seed", now=NOW)
        head = out[:20]
        from_mono = sum(1 for r in head if r["full_name"] == "mattpocock/skills")
        self.assertLessEqual(
            from_mono, CFG["diversity"]["max_owner_per_window"],
            f"首屏 20 条里有 {from_mono} 条来自同一个 monorepo",
        )
        self.assertGreaterEqual(len({r["full_name"] for r in head}), 10)

    def test_missing_stars_are_neutral_not_zero(self):
        """56/388 条没有 star 数据。缺数据 != 不受欢迎，不能系统性压制。"""
        rows = [item(f"has{k}", owner=f"o{k}", stars=5000 + k) for k in range(5)]
        for k, r in enumerate(rows):
            r["full_name"] = f"o{k}/has{k}"
        unknown = item("unknown", owner="ghost", stars=None)
        unknown["full_name"] = "ghost/unknown"
        unknown["stars"] = None
        allrows = rows + [unknown]
        ranking.annotate_repo_share(allrows, config=CFG)

        stock = ranking.shrink_to_neutral(
            ranking.raw_stock(unknown), unknown["_stock_neutral"],
            unknown["_star_share"])
        self.assertEqual(stock, unknown["_stock_neutral"])
        self.assertGreater(stock, 0.0)

    def test_neutral_is_repo_level_not_item_level(self):
        """一仓一票，否则 20 条的大仓会把中位数拉到自己身上。"""
        big = self._mono_fixed_name(20, stars=500000)
        smalls = []
        for k in range(5):
            r = item(f"s{k}", owner=f"d{k}", stars=100)
            r["full_name"] = f"d{k}/s{k}"
            smalls.append(r)
        ranking.annotate_repo_share(big + smalls, config=CFG)
        neutral = big[0]["_stock_neutral"]
        small_raw = ranking.raw_stock(smalls[0])
        big_raw = ranking.raw_stock(big[0])
        # 6 个仓库里 5 个是小仓，中位数应当靠近小仓那侧
        self.assertLess(neutral, (small_raw + big_raw) / 2)

    def test_velocity_is_shared_too(self):
        """同仓 20 条会记录 20 份完全相同的增速轨迹，增速同样是仓库级信号。"""
        rows = self._mono_fixed_name(4)
        for r in rows:
            r["stars_today"] = 300
        solo = item("solo", owner="indie", stars=245604, stars_today=300)
        solo["full_name"] = "indie/solo"
        ranking.annotate_repo_share(rows + [solo], config=CFG)
        g_mono, _ = ranking.global_quality(rows[0], config=CFG, now=NOW)
        g_solo, _ = ranking.global_quality(solo, config=CFG, now=NOW)
        self.assertLess(g_mono, g_solo)


class TestZeroDataColdStart(unittest.TestCase):
    """/api/events 上线时没有任何历史行为，退化路径必须是中性的。"""

    def test_ctr_is_neutral_with_no_traffic_at_all(self):
        gs = ranking.build_global_stats({}, [])
        self.assertEqual(gs.ctr_overall, 0.0)
        row = item("a")
        ranking.annotate_repo_share([row], config=CFG)
        self.assertEqual(ranking.ctr_ratio(row, None, gs, CFG), 1.0)
        self.assertEqual(ranking.ctr_ratio(row, ranking.ItemStats(), gs, CFG), 1.0)

    def test_ranking_still_orders_by_quality_with_zero_events(self):
        rows = [item("weak", owner="a", stars=30), item("strong", owner="b", stars=90000)]
        for r in rows:
            r["full_name"] = f"{r['owner']}/{r['name']}"
        out = ranking.rank_feed(rows, profile=None, stats={}, config=CFG, now=NOW)
        self.assertEqual(out[0]["id"], "strong")
        self.assertTrue(all(r["rank_slot"] == "main" for r in out))

    def test_ctr_part_does_not_penalise_unseen_items(self):
        gs = ranking.build_global_stats({}, [])
        row = item("a")
        ranking.annotate_repo_share([row], config=CFG)
        _, why = ranking.global_quality(row, stats=None, gstats=gs, config=CFG, now=NOW)
        self.assertIn("ctr:0.50", why)


class TestDiversity(unittest.TestCase):
    """约束是「只要还有别的可选就必须遵守」，不是「任何情况下都成立」。

    候选池被筛到只剩一个行业时，硬守约束的唯一办法是丢条目，那更糟。
    所以这里的断言都带「当时还有替代品」的前提。
    """

    def _rows(self, specs):
        return [item(f"i{n}", scene=s, l2=l2, owner=o) for n, (s, l2, o) in enumerate(specs)]

    def test_consecutive_scene_capped_while_alternatives_exist(self):
        rows = [
            item(f"i{n}", scene=f"s{n % 4}", l2=f"l{n}", owner=f"o{n}")
            for n in range(40)
        ]
        out = ranking.apply_diversity(rows, CFG)
        cap = CFG["diversity"]["max_consecutive_scene"]
        run = 1
        for i in range(1, len(out)):
            run = run + 1 if out[i]["scene"] == out[i - 1]["scene"] else 1
            if run > cap:
                # 只有「后面已经没有别的行业可选」才允许超限
                rest = {r["scene"] for r in out[i:]}
                self.assertEqual(
                    rest, {out[i]["scene"]},
                    f"位置 {i} 连续 {run} 条 {out[i]['scene']}，但后面还有 {rest}",
                )

    def test_owner_capped_per_window(self):
        rows = [item(f"h{n}", scene=f"s{n % 4}", l2=f"hl{n}", owner="hog") for n in range(6)]
        rows += [item(f"j{n}", scene=f"s{n % 4}", l2=f"l{n}", owner=f"o{n}") for n in range(30)]
        out = ranking.apply_diversity(rows, CFG)
        window = CFG["diversity"]["window"]
        for start in range(0, len(out) - window + 1):
            chunk = out[start:start + window]
            self.assertLessEqual(
                sum(1 for c in chunk if c["owner"] == "hog"),
                CFG["diversity"]["max_owner_per_window"],
            )

    def test_scene_run_is_actually_enforced(self):
        """直接验约束函数本身，避开候选池够不够的干扰。"""
        placed = [item("a", scene="design"), item("b", scene="design")]
        third = item("c", scene="design")
        self.assertTrue(ranking._violates(third, placed, CFG, 0, search=False))
        # 搜索态放宽到 4，第三条应当放行
        self.assertFalse(ranking._violates(third, placed, CFG, 0, search=True))
        # 放宽到 relax=4 时任何约束都不生效
        self.assertFalse(ranking._violates(third, placed, CFG, 4, search=False))

    def test_owner_cap_is_actually_enforced(self):
        placed = [
            item(f"p{n}", scene=f"s{n}", l2=f"l{n}", owner="hog")
            for n in range(CFG["diversity"]["max_owner_per_window"])
        ]
        nxt = item("next", scene="research", l2="wiki", owner="hog")
        self.assertTrue(ranking._violates(nxt, placed, CFG, 0, search=False))
        self.assertFalse(ranking._violates(nxt, placed, CFG, 3, search=False))

    def test_focus_cap_is_actually_enforced(self):
        cap = CFG["diversity"]["max_focus_per_window"]
        placed = []
        for n in range(cap):
            row = item(f"f{n}", scene=f"s{n}", l2=f"l{n}", owner=f"o{n}")
            row["_focus_hit"] = True
            placed.append(row)
        nxt = item("next", scene="research", l2="wiki", owner="zz")
        nxt["_focus_hit"] = True
        self.assertTrue(ranking._violates(nxt, placed, CFG, 0, search=False))
        # 非关注条目不受这条约束
        plain = item("plain", scene="research", l2="wiki", owner="zz")
        self.assertFalse(ranking._violates(plain, placed, CFG, 0, search=False))

    def test_set_is_preserved(self):
        """不变量：多样性重排不丢不重。"""
        rows = self._rows([("engineering", "infra", "acme")] * 25)
        out = ranking.apply_diversity(rows, CFG)
        self.assertEqual(len(out), len(rows))
        self.assertEqual({r["id"] for r in out}, {r["id"] for r in rows})

    def test_relaxes_instead_of_dropping(self):
        """候选池全是同一行业同一作者时必须放宽约束，而不是丢条目。"""
        rows = [item(f"same{n}", scene="design", l2="figma", owner="one") for n in range(30)]
        out = ranking.apply_diversity(rows, CFG)
        self.assertEqual(len(out), 30)

    def test_search_allows_longer_scene_runs(self):
        """搜 figma 就该大部分是设计类，硬打散反而伤相关性。"""
        rows = [item(f"d{n}", scene="design", l2=f"l{n}", owner=f"o{n}") for n in range(8)]
        rows += [item(f"e{n}", scene="engineering", l2=f"m{n}", owner=f"p{n}") for n in range(8)]

        def longest_run(seq):
            best = run = 1
            for i in range(1, len(seq)):
                run = run + 1 if seq[i]["scene"] == seq[i - 1]["scene"] else 1
                best = max(best, run)
            return best

        normal = longest_run(ranking.apply_diversity(rows, CFG, search=False))
        searched = longest_run(ranking.apply_diversity(rows, CFG, search=True))
        self.assertGreater(searched, normal)


class TestExploration(unittest.TestCase):
    def _profile(self):
        return ranking.DeviceProfile(
            device_id="d", affinity={"scene": {"content": (3.0, NOW)}}, events=20,
        )

    def _rows(self, n=20):
        rows = [item(f"i{k}", scene="content" if k < 10 else f"r{k % 3}",
                     l2=f"l{k}", owner=f"o{k}") for k in range(n)]
        for r in rows:
            r["global_score"] = 0.5
            r["_affinity"] = 0.3 if r["scene"] == "content" else -0.1
        return rows

    def test_slots_are_filled_and_nothing_is_lost(self):
        rows = self._rows()
        out = ranking.arrange_feed(rows, profile=self._profile(), config=CFG)
        self.assertEqual(len(out), len(rows))
        self.assertEqual({id(x) for x in out}, {id(x) for x in rows})
        for s in CFG["exploration"]["slots"]:
            self.assertEqual(out[s]["rank_slot"], "exploration")
            self.assertNotEqual(out[s]["scene"], "content")

    def test_ratio_is_15_percent(self):
        self.assertAlmostEqual(
            len(CFG["exploration"]["slots"]) / CFG["diversity"]["window"],
            CFG["exploration"]["ratio"],
            places=6,
        )

    def test_exploration_does_not_break_diversity(self):
        """探索位必须参与同一趟贪心：事后拼接会把同行业条目挤到一起。"""
        rows = self._rows(40)
        out = ranking.arrange_feed(rows, profile=self._profile(), config=CFG)
        cap = CFG["diversity"]["max_consecutive_scene"]
        run = 1
        for i in range(1, len(out)):
            run = run + 1 if out[i]["scene"] == out[i - 1]["scene"] else 1
            if run > cap:
                rest = {r["scene"] for r in out[i:]}
                self.assertEqual(rest, {out[i]["scene"]}, f"位置 {i} 连续 {run} 条")

    def test_no_profile_means_no_exploration_slots(self):
        """没有画像就无所谓破圈，硬标探索位只是给用户看不懂的标签。"""
        rows = self._rows()
        self.assertEqual(ranking.exploration_candidates(rows, None, CFG), [])
        out = ranking.arrange_feed(rows, profile=None, config=CFG)
        self.assertTrue(all(x.get("rank_slot") != "exploration" for x in out))

    def test_new_item_gets_a_slot(self):
        rows = self._rows()
        for r in rows:
            r["is_new"] = False
        rows[19]["is_new"] = True
        rows[19]["global_score"] = 0.01  # 分最低，只能靠配额出场
        out = ranking.arrange_feed(rows, profile=self._profile(), config=CFG)
        window = out[: CFG["diversity"]["window"]]
        explored = [x for x in window if x.get("rank_slot") == "exploration"]
        self.assertTrue(any(x.get("is_new") for x in explored))

    def test_suppressed_scene_still_reachable(self):
        """行业级压制对探索位无效——这是有意留的解封通道。"""
        rows = [item(f"i{n}", scene="research", l2=f"l{n}", owner=f"o{n}") for n in range(20)]
        for r in rows:
            r["global_score"] = 0.5
        profile = ranking.DeviceProfile(
            device_id="d",
            affinity={"scene": {"content": (3.0, NOW)}},
            suppress=[{"scope": "scene", "key": "research", "weight": 0.2,
                       "created_at": NOW.isoformat(),
                       "expires_at": (NOW + timedelta(days=28)).isoformat()}],
        )
        pool = ranking.exploration_candidates(rows, profile, CFG)
        self.assertTrue(pool)
        self.assertTrue(all(p["scene"] == "research" for p in pool))


class TestSessionStability(unittest.TestCase):
    def _rows(self):
        return [item(f"i{n}", scene=f"s{n % 4}", l2=f"l{n}", owner=f"o{n}",
                     stars=100 + n) for n in range(30)]

    def test_same_session_same_order(self):
        a = ranking.rank_feed(self._rows(), session_seed="dev:sess1", config=CFG, now=NOW)
        b = ranking.rank_feed(self._rows(), session_seed="dev:sess1", config=CFG, now=NOW)
        self.assertEqual([x["id"] for x in a], [x["id"] for x in b])

    def test_different_session_reshuffles(self):
        a = ranking.rank_feed(self._rows(), session_seed="dev:sess1", config=CFG, now=NOW)
        b = ranking.rank_feed(self._rows(), session_seed="dev:sess2", config=CFG, now=NOW)
        self.assertNotEqual([x["id"] for x in a], [x["id"] for x in b])

    def test_jitter_is_bounded(self):
        amp = CFG["session"]["jitter_amp"]
        for n in range(50):
            self.assertLessEqual(abs(ranking.session_jitter(f"k{n}", "seed", amp)), amp / 2)


class TestNegativeAndFatigue(unittest.TestCase):
    def _profile(self, scope, key, *, created, weight=None):
        spec = CFG["suppress"][scope]
        return ranking.DeviceProfile(
            device_id="d",
            suppress=[{
                "scope": scope, "key": key,
                "weight": weight if weight is not None else spec[0],
                "created_at": created.isoformat(),
                "expires_at": (created + timedelta(days=spec[1] * 4)).isoformat(),
            }],
        )

    def test_scene_penalty_halves_after_half_life(self):
        fresh = self._profile("scene", "engineering", created=NOW)
        aged = self._profile("scene", "engineering", created=NOW - timedelta(days=7))
        p_fresh, _, _ = ranking.negative_penalty(item("a"), fresh, CFG, NOW)
        p_aged, _, _ = ranking.negative_penalty(item("a"), aged, CFG, NOW)
        self.assertAlmostEqual(p_aged, p_fresh / 2, places=2)

    def test_scene_penalty_is_lighter_than_owner(self):
        """一级行业杀伤半径最大，惩罚必须最轻。"""
        scene_p, _, _ = ranking.negative_penalty(
            item("a"), self._profile("scene", "engineering", created=NOW), CFG, NOW)
        owner_p, _, _ = ranking.negative_penalty(
            item("a"), self._profile("owner", "acme", created=NOW), CFG, NOW)
        self.assertLess(scene_p, owner_p)

    def test_scene_penalty_expires_to_zero(self):
        old = self._profile("scene", "engineering", created=NOW - timedelta(days=60))
        p, _, _ = ranking.negative_penalty(item("a"), old, CFG, NOW)
        self.assertEqual(p, 0.0)

    def test_item_scope_hides(self):
        prof = self._profile("item", "a", created=NOW)
        _, hidden, _ = ranking.negative_penalty(item("a"), prof, CFG, NOW)
        self.assertTrue(hidden)

    def test_item_hide_expires(self):
        spec = CFG["suppress"]["item"]
        prof = ranking.DeviceProfile(device_id="d", suppress=[{
            "scope": "item", "key": "a", "weight": spec[0],
            "created_at": (NOW - timedelta(days=400)).isoformat(),
            "expires_at": (NOW - timedelta(days=1)).isoformat(),
        }])
        _, hidden, _ = ranking.negative_penalty(item("a"), prof, CFG, NOW)
        self.assertFalse(hidden)

    def test_fatigue_hard_block(self):
        prof = ranking.DeviceProfile(
            device_id="d", fatigue={"a": (6, NOW.isoformat())},
        )
        _, hidden, _ = ranking.negative_penalty(item("a"), prof, CFG, NOW)
        self.assertTrue(hidden)

    def test_fatigue_penalty_grows_then_decays(self):
        light = ranking.DeviceProfile(device_id="d", fatigue={"a": (1, NOW.isoformat())})
        heavy = ranking.DeviceProfile(device_id="d", fatigue={"a": (4, NOW.isoformat())})
        stale = ranking.DeviceProfile(
            device_id="d", fatigue={"a": (4, (NOW - timedelta(days=9)).isoformat())},
        )
        p_light, _, _ = ranking.negative_penalty(item("a"), light, CFG, NOW)
        p_heavy, _, _ = ranking.negative_penalty(item("a"), heavy, CFG, NOW)
        p_stale, _, _ = ranking.negative_penalty(item("a"), stale, CFG, NOW)
        self.assertLess(p_light, p_heavy)
        self.assertLess(p_stale, p_heavy)


class TestRuleConvergence(unittest.TestCase):
    """三条规则收敛成一个函数：回访 + 有关注时两项相加，不互斥。"""

    def _profile(self):
        return ranking.DeviceProfile(
            device_id="d",
            affinity={"scene": {"content": (3.0, NOW)}},
            focus=[("scene_l2", "writing")],
            events=20,
        )

    def test_double_hit_outranks_single(self):
        prof = self._profile()
        both = item("both", scene="content", l2="writing")
        only_behavior = item("beh", scene="content", l2="topic")
        neither = item("none", scene="research", l2="wiki")
        out = ranking.rank_feed(
            [neither, only_behavior, both], profile=prof, config=CFG, now=NOW,
        )
        by = {x["id"]: x["personal_score"] for x in out}
        self.assertGreater(by["both"], by["beh"])
        self.assertGreater(by["beh"], by["none"])

    def test_focus_works_without_any_history(self):
        """首次进入但选了关注：w_f 立刻满值，不用等画像攒够。"""
        cold = ranking.DeviceProfile(device_id="d", focus=[("scene", "content")], events=0)
        hit = item("hit", scene="content", l2="writing")
        miss = item("miss", scene="content", l2="writing")
        miss["scene"] = "research"
        out = ranking.rank_feed([miss, hit], profile=cold, config=CFG, now=NOW)
        self.assertEqual(out[0]["id"], "hit")
        self.assertGreater(out[0]["focus_score"], 0)

    def test_no_profile_is_pure_global(self):
        rows = [item("a", stars=10), item("b", stars=100000)]
        out = ranking.rank_feed(rows, profile=None, config=CFG, now=NOW)
        self.assertEqual(out[0]["id"], "b")
        self.assertEqual(out[0]["affinity_score"], 0.0)

    def test_hidden_items_are_dropped(self):
        prof = ranking.DeviceProfile(device_id="d", suppress=[{
            "scope": "item", "key": "gone", "weight": 1.0,
            "created_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(days=60)).isoformat(),
        }])
        out = ranking.rank_feed(
            [item("gone"), item("stay")], profile=prof, config=CFG, now=NOW,
        )
        self.assertEqual([x["id"] for x in out], ["stay"])


class TestSearchPriority(unittest.TestCase):
    def test_relevance_beats_personalization(self):
        """搜索时相关性必须压过个性化，否则用户搜什么都得到自己的老口味。"""
        prof = ranking.DeviceProfile(
            device_id="d", affinity={"scene": {"content": (6.0, NOW)}}, events=50,
        )
        relevant = item("figma-kit", scene="design", l2="figma",
                        description="figma plugin for design tokens")
        beloved = item("blog-writer", scene="content", l2="writing",
                       description="write blog posts quickly")
        out = ranking.rank_feed(
            [beloved, relevant], profile=prof, query="figma", config=CFG, now=NOW,
        )
        self.assertEqual(out[0]["id"], "figma-kit")

    def test_irrelevant_items_are_filtered(self):
        rows = [item("figma-kit", description="figma plugin"), item("zzz", description="nothing")]
        out = ranking.rank_feed(rows, query="figma", config=CFG, now=NOW)
        self.assertEqual([x["id"] for x in out], ["figma-kit"])

    def test_no_exploration_slots_while_searching(self):
        rows = [item(f"figma{n}", scene=f"s{n % 3}", l2=f"l{n}", owner=f"o{n}",
                     description="figma design tool") for n in range(20)]
        out = ranking.rank_feed(rows, query="figma", config=CFG, now=NOW)
        self.assertTrue(all(x.get("rank_slot") == "main" for x in out))

    def test_scene_filter_narrows(self):
        rows = [item("a", scene="content"), item("b", scene="design")]
        out = ranking.rank_feed(rows, scene_filter="design", config=CFG, now=NOW)
        self.assertEqual([x["id"] for x in out], ["b"])


class TestSimilarity(unittest.TestCase):
    def test_same_l2_scores_higher_than_same_l1(self):
        base = item("a", scene="content", l2="writing")
        same_l2 = item("b", scene="content", l2="writing", owner="other")
        same_l1 = item("c", scene="content", l2="podcast", owner="other")
        far = item("d", scene="engineering", l2="infra", owner="other")
        self.assertGreater(ranking.similarity(base, same_l2), ranking.similarity(base, same_l1))
        self.assertGreater(ranking.similarity(base, same_l1), ranking.similarity(base, far))

    def test_lookalike_uses_max_not_mean(self):
        base = item("a", scene="content", l2="writing")
        liked = [item("far", scene="engineering", l2="infra", owner="x")] * 9
        liked.append(item("near", scene="content", l2="writing", owner="y"))
        self.assertGreater(ranking.lookalike_score(base, liked), 0.4)


if __name__ == "__main__":
    unittest.main()
