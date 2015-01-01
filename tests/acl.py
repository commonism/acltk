import glob
import unittest
from acltk import ACLConfig


class aclTestParse(unittest.TestCase):
	def test_all(self):
		cfg = ACLConfig.parse("acl/all.conf")
		self.assertIsNotNone(cfg)
		cfg.names.__repr__()
		for i in cfg.interfaces.values():
			i.__repr__()
		for i in cfg.objects.time.values():
			i.__repr__()
		for i in cfg.groups.icmp.values():
			i.__repr__()
		for i in cfg.rules.rules:
			i.__repr__()

	def test_private(self):
		for i in glob.glob('acl/private/*.conf'):
			cfg = ACLConfig.parse(i)
			self.assertIsNotNone(cfg)
			cfg.name
			cfg.names.__repr__()
			for i in cfg.interfaces:
				i.__repr__()
			for i in cfg.objects.icmp.values():
				i.__repr__()
			for i in cfg.objects.time.values():
				i.__repr__()
			for i in cfg.rules.rules:
				i.__repr__()

