import glob
import unittest

from jinja2 import FileSystemLoader, Environment
from jinja2.utils import concat

import tatsu.exceptions

from acltk import ACLConfig
from acltk.cafObjects import cafBlock
from acltk.fwsmObjects import fwsmConfig


class cafTestParse(unittest.TestCase):
    good = ["comments", "localhosts", "multi_addr", "nested", "single", "multi_addr", "v6", "any", "README"]
    bad = ["multi_id"]

    def test_good(self):
        for i in self.good:
            print(i)
            cfg = cafBlock.fromPath(f"caf/{i}.caf")
            self.assertIsNotNone(cfg)

    def test_bad(self):
        for i in self.bad:
            with self.assertRaises(tatsu.exceptions.FailedParse):
                cafBlock.fromPath(f"caf/{i}.caf")

    def test_private(self):
        for i in glob.glob("acl/private/*.conf"):
            print(i)
            acl = ACLConfig.fromPath(i)
            for j in glob.glob("caf/private/*.caf"):
                print(j)
                cfg = cafBlock.fromPath(j)
                r = cfg.run(acl.rules, verbose=True)
                self.assertTrue(len(r) >= 0)
                acl.resolve(r)
            for i in cafTestParse.good:
                cfg = cafBlock.fromPath(f"caf/{i}.caf")
                r = cfg.run(acl.rules, verbose=True)
                self.assertTrue(len(r) >= 0)
                acl.resolve(r)


class cafTestRun(unittest.TestCase):
    def setUp(self):
        loader = FileSystemLoader("./acl/tpl/")
        env = Environment(loader=loader, extensions=[])
        self.tpl = env.get_template("fwsm.jinja2")
        self.ctx = self.tpl.new_context({})

        data = concat(self.tpl.blocks["all"](self.ctx))
        self.acls = fwsmConfig.fromString(data)

    def _test_single_caf(self, name):
        cfg = cafBlock.fromPath(f"caf/{name}.caf")
        r = cfg.run(self.acls.rules, verbose=True)
        # 		self.assertTrue(len(r) >= 0)
        self.acls.resolve(r)
        return r

    def test__any(self):
        return self._test_single_caf("any")

    def test__comments(self):
        return self._test_single_caf("comments")

    def test__empty_id(self):
        with self.assertRaises(tatsu.exceptions.FailedParse):
            self._test_single_caf("empty_id")

    def test__fnmatch_id(self):
        self._test_single_caf("fnmatch_id")

    def test__localhosts(self):
        return self._test_single_caf("localhosts")

    def test__multi_addr(self):
        return self._test_single_caf("multi_addr")

    def test__multi_id(self):
        with self.assertRaises(tatsu.exceptions.FailedParse):
            self._test_single_caf("multi_id")

    def test__nested(self):
        return self._test_single_caf("nested")

    def test__single(self):
        return self._test_single_caf("single")

    def test__v6(self):
        return self._test_single_caf("v6")

    def test_expand(self):
        self.acls.expand()

    def test_public(self):
        for i in cafTestParse.good:
            print(i)
            cfg = cafBlock.fromPath(f"caf/{i}.caf")
            r = cfg.run(self.acls.rules, verbose=True)
            self.assertTrue(len(r) >= 0)
            self.acls.resolve(r)


class cafTestFilter(unittest.TestCase):
    def setUp(self):
        loader = FileSystemLoader("./acl/tpl/")
        env = Environment(loader=loader, extensions=[])
        self.tpl = env.get_template("caf.jinja2")
        data = self.tpl.render()
        self.acls = fwsmConfig.fromString(data)

    def rules_by_id(self, *_id):
        return [i for i in filter(lambda x: x.id in set(_id), self.acls.rules.rules)]

    def test_filter_(self):
        cfg = cafBlock.fromString("id caf_filter_")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

    def test_filter_0(self):
        cfg = cafBlock.fromString("id caf_filter_0 ip src 1.1.1.1 ip dst 2.2.2.2")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_0"))

        cfg = cafBlock.fromString("id caf_filter_0 ip src 1.1.1.2 ip dst 2.2.2.2")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

        cfg = cafBlock.fromString("id caf_filter_0 ip src 1.1.1.1 ip dst 2.2.2.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

    def test_filter_1(self):
        cfg = cafBlock.fromString("id caf_filter_1 ip src 1.1.1.1 ip dst 2.2.2.2")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_1"))

        cfg = cafBlock.fromString("id caf_filter_1 ip src 1.1.1.2 ip dst 2.2.2.2")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

        cfg = cafBlock.fromString("id caf_filter_1 ip src 1.1.1.1 ip dst 2.2.2.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

    def test_filter_2(self):
        cfg = cafBlock.fromString("id caf_filter_2 ip src 1.1.1.2 ip dst 2.2.2.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_2"))

        cfg = cafBlock.fromString("id caf_filter_2 ip src 1.1.2.2 ip dst 2.2.2.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

        cfg = cafBlock.fromString("id caf_filter_2 ip src 1.1.1.2 ip dst 2.2.3.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

    def test_filter_3(self):
        cfg = cafBlock.fromString("id caf_filter_3 ip src 1.1.1.1 ip dst 2.2.2.2")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_3"))

        cfg = cafBlock.fromString("id caf_filter_3 ip src 1.1.2.2 ip dst 2.2.2.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

        cfg = cafBlock.fromString("id caf_filter_3 ip src 1.1.1.2 ip dst 2.2.3.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

    def test_filter_4(self):
        cfg = cafBlock.fromString("id caf_filter_4 ip src 1.1.1.2 ip dst 2.2.2.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_4"))

        cfg = cafBlock.fromString("id caf_filter_4 ip src 1.1.2.2 ip dst 2.2.2.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

        cfg = cafBlock.fromString("id caf_filter_4 ip src 1.1.1.2 ip dst 2.2.3.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

    def test_filter_5(self):
        cfg = cafBlock.fromString("id caf_filter_5 ip src 1.1.1.2 ip dst 2.2.2.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_5"))

        cfg = cafBlock.fromString("id caf_filter_5 ip src 1.1.2.2 ip dst 2.2.2.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

        cfg = cafBlock.fromString("id caf_filter_5 ip src 1.1.1.2 ip dst 2.2.3.3")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

        cfg = cafBlock.fromString("id caf_filter_5 ip src 1.1.1.0/24 ip dst 2.2.2.0/24")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_5"))

    def test_op_intersect(self):
        cfg = cafBlock.fromString("id caf_filter_5 intersect id caf_filter_5")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_5"))

        cfg = cafBlock.fromString("id caf_filter_5 intersect id caf_filter_")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_"))

    def test_op_union(self):
        cfg = cafBlock.fromString("id caf_filter_5 union id caf_filter_4")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_5", "caf_filter_4"))

        cfg = cafBlock.fromString("id caf_filter_5 union id caf_filter_")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_5"))

    def test_op_except(self):
        cfg = cafBlock.fromString("id /caf_filter_[012345]/ except id /caf_filter_[01234]/")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_5"))

        cfg = cafBlock.fromString("id caf_filter_5 except id caf_filter_")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_5"))

    def test_filter_6(self):
        cfg = cafBlock.fromString("id /caf_filter_6[12]/ except (ip src ANY ANY4 ANY6 union ip dst ANY ANY4 ANY6)")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_61"))

        cfg = cafBlock.fromString("id caf_filter_62 ip src ANY ANY4 ANY6 ip dst ANY ANY4 ANY6")
        a = cfg.run(self.acls.rules, verbose=True)
        b = self.rules_by_id("caf_filter_62")
        self.assertCountEqual(a, b)

    def test_filter_7(self):
        import acltk

        g = self.acls.groups.network["NetworkGroup7"]

        g.objects = [acltk.aclObjects.NetworkAny()]
        cfg = cafBlock.fromString("id caf_filter_7 ip src ANY")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), self.rules_by_id("caf_filter_7"))

        cfg = cafBlock.fromString("id caf_filter_7 except ip src ANY")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), [])

        g.objects = [acltk.aclObjects.NetworkAny4()]
        cfg = cafBlock.fromString("id caf_filter_7 except ip src ANY4")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), [])

        g.objects = [acltk.aclObjects.NetworkAny6()]
        cfg = cafBlock.fromString("id caf_filter_7 except ip src ANY6")
        self.assertCountEqual(cfg.run(self.acls.rules, verbose=True), [])
