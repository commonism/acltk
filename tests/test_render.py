import os
import unittest
from jinja2 import FileSystemLoader, Environment
from acltk import ACLConfig, cafBlock
from acltk.aclObjects import (
    NetworkGroup,
    PortGroup,
    ServiceGroup,
    ProtocolGroup,
    TimeRange,
    Network,
    NetworkHost,
    NetworkObject,
    ServiceObject,
    ACLParserOptions,
)
from acltk.pfsenseObjects import pfsenseConfig

RENDER_DIR = "../examples/render/"


def renderpath(p):
    return os.path.abspath(os.path.normpath(os.path.join("../examples/render/", p)))


class renderTest(unittest.TestCase):

    SORT_ALL = ("network", "service", "port", "protocol")

    def setUp(self):
        loader = FileSystemLoader(renderpath("tpl/"))
        env = Environment(loader=loader, extensions=["jinja2.ext.loopcontrols"])
        self.template = env.get_template("static.html")

    def _test_render_single(self, aclpath, cafpath, sort=None, trace=False):
        acl = ACLConfig.fromPath(aclpath, options=ACLParserOptions(trace=trace))
        if False:
            acl.expand()

        if cafpath:
            caf = cafBlock.fromPath(cafpath, trace=False)
            r = acl.filter(caf)
            selection = acl.resolve(r)
        else:
            selection = None

        for i in sort or []:  #:
            grps = getattr(acl.groups, i)
            for grp in grps.values():
                grp.sort()

        try:
            if cafpath:
                path = "dataout/{}-{}.html".format(
                    *list(map(lambda x: os.path.splitext(os.path.basename(x))[0], [aclpath, cafpath]))
                )
            else:
                path = "dataout/{}.html".format(
                    *list(map(lambda x: os.path.splitext(os.path.basename(x))[0], [aclpath]))
                )
        except Exception as e:
            print(e)

        with open(path, "w") as f:
            f.write(self.template.render(aclconfig=acl, selection=selection, caf=cafpath, args={}))

    def test_render_this(self):
        return self._test_render_single("acl/single/all-network_object_nat_any.txt", None, sort=self.SORT_ALL)

    def test_render_all(self):
        return self._test_render_single("acl/single/all.txt", "caf/any.caf", sort=self.SORT_ALL)

    def test_render_auto(self):
        return self._test_render_single("acl/single/auto.txt", "caf/any.caf", sort=self.SORT_ALL, trace=False)
