import os
import glob
import unittest

from jinja2 import FileSystemLoader, Environment
from jinja2.utils import concat


from acltk.fwsmObjects import fwsmConfig
from acltk.iosObjects import iosConfig
from acltk.pfsenseObjects import pfsenseConfig, pfsenseParserOptions
from acltk.aclObjects import NetworkWildcard, NetworkHost, Network, ACLConfig, ACLParserOptions, PortUtil


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
		for i in [{'fetch_urltable':False},{'fetch_urltable':True}]:
			cfg = pfsenseConfig.fromPath("acl/pfsense.xml", options=pfsenseParserOptions(**i))
			self.assertIsNotNone(cfg)
			cfg.names.__repr__()
			for i in cfg.interfaces.values():
				i.__repr__()
			for i in cfg.rules.rules:
				i.__repr__()

	def test_pf_1_s5(self):
		cfg = pfsenseConfig.fromPath("acl/config-pf-1-s5.xml")
		self.assertIsNotNone(cfg)
		cfg.names.__repr__()
		for i in cfg.interfaces.values():
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

	def _test_single_acl(self, name, trace=False):
		cfg = ACLConfig.fromPath(name, options=ACLParserOptions(trace=trace))

	def test_candidate(self):
		return self._test_single_acl('acl/private/fwsm.conf')
#		return self._test_single_acl('acl/supportforums.cisco.com/run_config_asa.txt')

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

class aclTestBlock(unittest.TestCase):
	def setUp(self):
		loader = FileSystemLoader('./acl/tpl/')
		env = Environment(loader=loader, extensions=[])
		self.tplargs = {'services':list(PortUtil.services())}
		self.tpl = {}
		self.ctx = {}
		for tpl in env.list_templates():
			name = os.path.splitext(tpl)[0]
			self.tpl[name] = env.get_template(tpl)
			self.ctx[name] = self.tpl[name].new_context(self.tplargs)

	def _test_block(self, block, deps=None, tpl='all', trace=False):
#		print(self.tpl[tpl].blocks.keys())
		if block is not None:
			fname = 'acl/single/{tpl}-{block}.txt'
			blocks = [block]
			if deps:
				blocks.extend(deps)
			data = ''
			for b in blocks[::-1]:
				data += concat(self.tpl[tpl].blocks[b](self.ctx[tpl]))
		else:
			fname = 'acl/single/{tpl}.txt'
			data = self.tpl[tpl].render(**self.tplargs)

		fname = fname.format(**{'tpl':tpl,'block':block})

		with open(fname, 'wt') as f:
			f.write(data)

		cfg = fwsmConfig.fromPath(fname, options=ACLParserOptions(trace=trace))

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

	def test_block_access_list_rule_webtype(self):
		return self._test_block('access_list_rule_webtype', trace=False)

	def test_block_access_list_rule_ethertype(self):
		return self._test_block('access_list_rule_ethertype')

	def test_block_access_list_log_level(self):
		return self._test_block('access_list_log_level')

	def test_block_access_list_rule_protocol(self):
		return self._test_block('access_list_rule_protocol')

	def test_block_access_list_rule_protocol_int(self):
		return self._test_block('access_list_rule_protocol_int')

	def test_block_access_list_rule_expand(self):
		return self._test_block('access_list_rule_expand', ['object_group_expand'])

	def test_block_object_group_service_int(self):
		return self._test_block('object_group_service_int')

	def test_block_object_service_int(self):
		return self._test_block('object_service_int')

	def test_block_nat(self):
		return self._test_block('nat', ['nat_interfaces'], trace=True)

	def test_block_network_object_dynamic_nat(self):
		return self._test_block('network_object_dynamic_nat', trace=True)

	def test_block_nat_and_interfaces(self):
		return self._test_block('nat_and_interfaces', ['nat_interfaces'], trace=True)

	def test_block_nat_twice_pat(self):
		return self._test_block('twice_dynamic_pat', ['nat_interfaces'], trace=True)

	def test_block_nat_twice_static_nat(self):
		return self._test_block('twice_static_nat', ['nat_interfaces'], trace=True)

	def test_block_nat_twice_dynamic_pat_dest_host_port(self):
		return self._test_block('twice_dynamic_pat_dest_host_port', ['nat_interfaces'], trace=True)

	def test_block_network_object_dynamic_nat_backup_pat(self):
		return self._test_block('network_object_dynamic_nat_backup_pat', ['nat_interfaces'], trace=True)

	def test_block_network_object_nat_single_definition(self):
		return self._test_block('network_object_nat_single_definition', ['nat_interfaces'], trace=True)

	def test_block_nat_mapped_network_group(self):
		return self._test_block('nat_mapped_network_group', ['nat_interfaces'], trace=True)

	def test_all(self):
		return self._test_block(None, tpl='all')

	def test_bad(self):
		for name in self.tpl['bad'].blocks.keys():
			print("Processing {}".format(name))
			with self.assertRaises(Exception) as e:
				self._test_block(name, tpl='bad')

			for i in str(e.exception).split('\n'):
				print('>\t{}'.format(i))
			print('')

	def test_auto(self):
		return self._test_block(None, tpl='auto')