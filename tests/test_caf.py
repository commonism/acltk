import glob
import unittest
import tatsu.exceptions
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
			with self.assertRaises(tatsu.exceptions.FailedParse):
				cafBlock.fromPath("caf/{}.caf".format(i))


class cafTestFilter(unittest.TestCase):
	def setUp(self):
		self.acls = fwsmConfig.fromPath('acl/all.conf')

	def _test_single_caf(self, name):
		cfg = cafBlock.fromPath("caf/{}.caf".format(name))
		r = cfg.run(self.acls.rules, verbose=True)
#		self.assertTrue(len(r) >= 0)
		self.acls.resolve(r)
		return r

	def test__any(self):
		return self._test_single_caf('any')

	def test__comments(self):
		return self._test_single_caf('comments')

	def test__empty_id(self):
		with self.assertRaises(tatsu.exceptions.FailedParse):
			self._test_single_caf('empty_id')

	def test__fnmatch_id(self):
		self._test_single_caf('fnmatch_id')

	def test__localhosts(self):
		return self._test_single_caf('localhosts')

	def test__multi_addr(self):
		return self._test_single_caf('multi_addr')

	def test__multi_id(self):
		with self.assertRaises(tatsu.exceptions.FailedParse):
			self._test_single_caf('multi_id')

	def test__nested(self):
		return self._test_single_caf('nested')

	def test__single(self):
		return self._test_single_caf('single')

	def test__v6(self):
		return self._test_single_caf('v6')

	def test_expand(self):
		self.acls.expand()

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

	def test_public(self):
		for i in cafTestParse.good:
			print(i)
			cfg = cafBlock.fromPath("caf/{}.caf".format(i))
			r = cfg.run(self.acls.rules, verbose=True)
			self.assertTrue(len(r) >= 0)
			self.acls.resolve(r)
