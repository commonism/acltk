import datetime
import os
import unittest
from jinja2 import FileSystemLoader, Environment
from acltk import ACLConfig, cafBlock
from acltk.aclObjects import NetworkGroup, PortGroup, ServiceGroup, ProtocolGroup, TimeRange, Network, NetworkHost, \
	NetworkObject, ServiceObject
from acltk.pfsenseObjects import pfsenseConfig

RENDER_DIR = "../examples/render/"

def renderpath(p):
	return os.path.abspath(os.path.normpath(os.path.join("../examples/render/",p)))

class renderTest(unittest.TestCase):

	SORT_ALL = ('network','service','port','protocol')

	def setUp(self):
		loader = FileSystemLoader(renderpath('tpl/'))
		env = Environment(loader=loader, extensions=['jinja2.ext.loopcontrols'])
		self.template = env.get_template('static.html')


	def _test_render_single(self, aclpath, cafpath, sort=None):
		acl = ACLConfig.fromPath(aclpath)
		if False:
			acl.expand()
		caf = cafBlock.fromPath(cafpath, trace=False)

		r = caf.run(acl.rules, verbose=True)
		selection = acl.resolve(r)

		for i in sort or []: #:
			grps = getattr(acl.groups, i)
			for grp in grps.values():
				grp.sort()




		try:
			path = "dataout/{}-{}.html".format(*list(map(lambda x: os.path.splitext(os.path.basename(x))[0], [aclpath, cafpath])))
		except Exception as e:
			print(e)

		with open(path,'wt') as f:
			f.write(self.template.render(aclconfig=acl, selection=selection, caf=cafpath, args={}))

	def test_render_all(self):
		return self._test_render_single('acl/single/all.txt', 'caf/any.caf', sort=self.SORT_ALL)
