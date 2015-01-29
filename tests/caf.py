import glob
import unittest
import grako.exceptions
from acltk import ACLConfig

from acltk.cafObjects import cafBlock
from acltk.fwsmObjects import fwsmConfig


class cafTestParse(unittest.TestCase):
	good = ["comments","localhosts","multi_addr","nested","single","multi_addr","v6","any", "README"]
	bad = ["multi_id"]

	def test_good(self):
		for i in self.good:
			print(i)
			cfg = cafBlock.fromPath("caf/{}.caf".format(i))
			self.assertIsNotNone(cfg)

	def test_bad(self):
		for i in self.bad:
			with self.assertRaises(grako.exceptions.FailedParse):
				cafBlock.fromPath("caf/{}.caf".format(i))


class cafTestFilter(unittest.TestCase):
	def setUp(self):
		self.acls = fwsmConfig.fromPath('acl/all.conf')

	def test_public(self):
		for i in cafTestParse.good:
			cfg = cafBlock.fromPath("caf/{}.caf".format(i))
			r = cfg.run(self.acls.rules, verbose=True)
			self.assertTrue(len(r) >= 0)
			self.acls.resolve(r)

	def test_private(self):
		for i in glob.glob("acl/private/*.conf"):
			print(i)
			acl = ACLConfig.fromPath(i)
			for j in glob.glob('caf/private/*.caf'):
				print(j)
				cfg = cafBlock.fromPath(j)
				r = cfg.run(acl.rules, verbose=True)
				self.assertTrue(len(r) >= 0)
				acl.resolve(r)
			for i in cafTestParse.good:
				cfg = cafBlock.fromPath("caf/{}.caf".format(i))
				r = cfg.run(acl.rules, verbose=True)
				self.assertTrue(len(r) >= 0)
				acl.resolve(r)

	def test_expand(self):
		self.acls.expand()