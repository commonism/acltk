import glob
import unittest
from acltk.fwsmObjects import fwsmConfig
from acltk.iosObjects import iosConfig
from acltk.aclObjects import NetworkWildcard, NetworkHost, Network, ACLConfig


class aclTestObjects(unittest.TestCase):
	def test_NetworkWildcard(self):
		n = NetworkWildcard('127.0.0.0', '0.0.0.254')
		print(n._addresses())
		self.assertTrue(n & NetworkHost('127.0.0.2'))
		self.assertFalse(n & NetworkHost('127.0.0.1'))
		self.assertTrue(n & Network('127.0.0.0', '255.255.255.254'))
		self.assertFalse(n & Network('127.0.0.1', '255.255.255.255'))


class aclTestParse(unittest.TestCase):
	def test_all(self):
		cfg = fwsmConfig.fromPath("acl/all.conf")
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

	def test_ios(self):
		cfg = iosConfig.fromPath("acl/ios.txt")
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
			print(i)
			cfg = ACLConfig.fromPath(i)
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

