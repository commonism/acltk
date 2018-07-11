import glob
import unittest
from acltk.fwsmObjects import fwsmConfig
from acltk.iosObjects import iosConfig
from acltk.pfsenseObjects import pfsenseConfig
from acltk.aclObjects import NetworkWildcard, NetworkHost, Network, ACLConfig


class aclTestObjects(unittest.TestCase):
	def test_NetworkWildcard(self):
		# only addresses with first bit unset - only addresses with last octet multiple of 2
		n = NetworkWildcard('127.0.0.0', '0.0.0.254')
		print(sorted(n._addresses()))
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

	def test_pfsense(self):
		cfg = pfsenseConfig.fromPath("acl/pfsense.xml")
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


	def test_ignored(self):
		cfg = fwsmConfig.fromPath("acl/ignored.txt")
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

	def _test_single_acl(self, name):
		cfg = ACLConfig.fromPath(name)

	def _test_candidate(self):
#		return self._test_single_acl('acl/private/fwsm-s5_nsc-003.conf')
		return self._test_single_acl('acl/supportforums.cisco.com/run_config_asa.txt')

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

from jinja2 import FileSystemLoader, Environment
from jinja2.utils import concat


class aclTestBlock(unittest.TestCase):
	def setUp(self):
		loader = FileSystemLoader('./acl/tpl/')
		env = Environment(loader=loader, extensions=[])
		self.tpl = env.get_template('all.jinja2')
		self.ctx = self.tpl.new_context({})

	def _test_block(self, block, deps=None):
		blocks = [block]
		if deps:
			blocks.extend(deps)
		data = ''
		for b in blocks[::-1]:
			data += concat(self.tpl.blocks[b](self.ctx))
			cfg = fwsmConfig.fromString(data)

	def test_block_names(self):
		return self._test_block('names')

	def test_block_interfaces(self):
		return self._test_block('interfaces')

	def test_block_interface_with_trailing_ws(self):
		return self._test_block('interface_with_trailing_ws')

	def test_block_time_ranges(self):
		return self._test_block('time_ranges')

	def test_block_object_service(self):
		return self._test_block('object_service')

	def test_block_object_group_icmp_type(self):
		return self._test_block('object_group_icmp_type')

	def test_block_object_group_service(self):
		return self._test_block('object_group_service', ['object_service','object_group_icmp_type'])

	def test_block_object_network(self):
		return self._test_block('object_network')

	def test_block_object_group_network(self):
		return self._test_block('object_group_network', ['names','object_network'])

	def test_block_object_protocol(self):
		return self._test_block('object_protocol')

	def test_all(self):
		return self._test_block('all')

