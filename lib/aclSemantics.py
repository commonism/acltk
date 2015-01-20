import datetime
import ipaddress

from grako.parsing import graken

from acltk.aclObjects import TimeRangeObjectAbsolute, TimeRangeObjectPeriodic, TimeRange, \
	NetworkObject, ServiceObject, NetworkGroup, PortGroup, ServiceGroup, ProtocolGroup, ICMPGroup, Protocol, ICMP, \
	NetworkHost, Network, Service, PortRange, Port, ACLNode, NetworkAny, Interface, NetworkAny4, NetworkAny6, \
	ACLRuleOptionInActive, ACLRuleOptionLog, NetworkInterface, Name


class aclSemantics:
	def __init__(self, parser):
		self.parser = parser

	def SP(self, ast):
		return None

	def WS(self, ast):
		return None

	def interface(self, ast):
		iface = Interface(ast['alias'])
		for i in ast['detail']:
			for k, v in i.items():
				if v is not None:
					setattr(iface, k, v)
		return iface

	def interface_detail(self, ast):
		return None

	def hour(self, ast):
		return int(ast)

	def minute(self, ast):
		return int(ast)

	def day(self, ast):
		return int(ast)

	def month(self, ast):
		return {
			"January": 1,
			"February": 2,
			"March": 3,
			"April": 4,
			"May": 5,
			"June": 6,
			"July": 7,
			"August": 8,
			"September": 9,
			"October": 10,
			"November": 11,
			"December": 12
		}[ast]

	def year(self, ast):
		return int(ast)

	def time(self, ast):
		return datetime.time(**ast)

	def timedate(self, ast):
		return datetime.datetime(**ast)

	def time_range_object(self, ast):
		assert ast.type in ('no','absolute','periodic')
		if ast.type == 'no':
			return None
		elif ast.type == 'absolute':
			return TimeRangeObjectAbsolute(ast.start, ast.end)
		elif ast.type == 'periodic':
			return TimeRangeObjectPeriodic(ast.start, ast.days, ast.end, ast.edays)

	def time_range(self, ast):
		t = TimeRange(ast.name)
		self.parser.time_ranges[ast.name] = t
		for i in ast.objects:
			t.add(i)
		return t

	def object_type(self, ast):
		action = {
			'network': (NetworkObject, self.parser.network_objects),
			'service': (ServiceObject, self.parser.service_objects),
		}

		cls, groups = action[ast.type]
		p = cls(ast.name, ast.description, **ast['args'])
		groups[ast.name] = p
		return p

	def object(self, ast):
		return ast[1]

	def object_group(self, ast):
		return ast[1]

	def object_group_type(self, ast):
		action = {
			'network': (NetworkGroup, self.parser.network_groups),
			'service': (ServiceGroup, self.parser.service_groups),
			'tcp': (lambda name, d: PortGroup(name, Protocol('tcp'), description=d), self.parser.service_groups),
			'udp': (lambda name, d: PortGroup(name, Protocol('udp'), description=d), self.parser.service_groups),
			'tcp-udp': (lambda name, d: PortGroup(name, Protocol('tcp-udp'), description=d), self.parser.service_groups),
			'icmp-type': (ICMPGroup, self.parser.icmp_groups),
			'protocol': (ProtocolGroup, self.parser.protocol_groups),
		}

		cls, groups = action[ast.type]
		p = cls(ast.name, ast.description)
		groups[ast.name] = p
		for i in ast.objects:
			p.add(i)
		return p

	def _resolve_addr(self, addr):
		target = None
		try:
			ipaddress.ip_address(addr)
		except ValueError:
			target = self.parser.names[addr]
			addr = str(self.parser.names[addr].address)
			return addr, target
		return addr, target

	def protocol_icmp(self, ast):
		return Protocol(ast)

	def protocol(self, ast):
		return Protocol(ast)

	def network_group_object(self, ast):
		if ast.type is None:
			return None
		if ast.type == 'network-object':
			if ast.name == 'object':
				# pdb.set_trace()
				return self.parser.network_objects[ast.object]

			if ast.name == 'host':
				addr = ast.address
			else:
				addr = ast.name

			addr, target = self._resolve_addr(addr)

			if ast.name == 'host':
				return NetworkHost(addr, target)
			else:
				return Network(addr, ast.netmask, target)

		elif ast.type == 'group-object':
			return self.parser.network_groups[ast.object]

	def service_group_object(self, ast):
		if ast.type is None:
			return None
		if ast.type == 'service-object':
			if ast.protocol == 'object':
				return self.parser.service_objects[ast.object]
			else:
				del ast['type']
				if 'object' in ast:
					del ast['object']
				return Service(**ast)
		elif ast.type == 'group-object':
			r = self.parser.service_groups[ast.object]
			return r

	def service_object_op(self, ast):
		if ast[0] == 'range':
			return PortRange(ast[1], ast[2])
		else:
			return Port(ast[0], ast[1])

	def port_group_object(self, ast):
		if ast is None:
			return
		# pdb.set_trace()
		if ast[0] == 'port-object':
			if ast[1] == 'range':
				return PortRange(ast[2], ast[3])
			else:
				return Port(ast[1], ast[2])
		elif ast[0] == 'group-object':
			return self.parser.service_groups[ast[1]]

	def protocol_group_object(self, ast):
		if ast.type is None:
			return None
		if ast.type == 'protocol-object':
			return Protocol(ast.name)
		elif ast.type == 'group-object':
			return self.parser.protocol_groups[ast.name]

	def icmp_group_object(self, ast):
		if ast.type is None:
			return None
		if ast.type == 'icmp-object':
			return ICMP(ast.name, None)
		elif ast.type == 'group-object':
			return self.parser.icmp_groups[ast.name]

	def acl_protocol(self, ast):
		if hasattr(ast, 'type') and ast.type is not None:
			if ast.type == 'object':
				return self.parser.service_objects[ast.name]
			elif ast.type == 'object-group':
				if ast.name in self.parser.service_groups:
					return self.parser.service_groups[ast.name]
				else:
					return self.parser.protocol_groups[ast.name]
		else:
			return Protocol(ast.name)

	def acl_host(self, ast):
		if hasattr(ast, 'type') and ast.type is not None:
			# pdb.set_trace()
			if ast.type == 'host' or ast.type == 'ip':
				addr, target = self._resolve_addr(ast.address)
				return NetworkHost(addr, target=target)
			elif ast.type == 'interface':
				return NetworkInterface(ast.name)
			elif ast.type in ('any', 'any4', 'any6'):
				return {'any':NetworkAny(),'any4':NetworkAny4(), 'any6':NetworkAny6()}[ast.type]
			elif ast.type == 'object':
				return self.parser.network_objects[ast.name]
			elif ast.type == 'object-group':
				return self.parser.network_groups[ast.name]
		else:
			addr, target = self._resolve_addr(ast.address)
			return Network(addr, ast.netmask, target=target)

	def acl_port(self, ast):
		if hasattr(ast, 'type') and ast.type is not None:
			if ast.type == 'range':
				return PortRange(ast.start, ast.stop)
			elif ast.type == 'object-group':
				return self.parser.service_groups[ast.name]
		else:
			return Port(ast.op, ast.port)

	def acl_icmp_node(self, ast):
		return ACLNode(ast, None)

	def acl_icmp_options(self, ast):
		if ast.type is None:
			return None
		if ast.type == 'object-group':
			return self.parser.icmp_groups[ast.object]
		else:
			return ICMP(ast.type, ast.code)

	def node(self, ast):
		return ACLNode(ast.host, ast.port)

	def acl_options(self, ast):
		r = {}
		for i in ast:
			assert i.type is None or i.type in ('log','time-range','inactive')
			if i.type is None:
				continue
			elif i.type == 'log':
				r[i.type] = ACLRuleOptionLog(i.options)
			elif i.type == 'time-range':
				r[i.type] = self.parser.time_ranges[i.option]
			elif i.type == 'inactive':
				r[i.type] = ACLRuleOptionInActive()
		return r


class aclParser:
	def __init__(self):
		self.network_groups = dict()
		self.network_objects = dict()
		self.service_groups = dict()
		self.service_objects = dict()
		self.port_groups = dict()
		self.icmp_groups = dict()
		self.protocol_groups = dict()
		self.names = dict()
		self.time_ranges = dict()

	def __acl_internal_ids(self, s):
		if len(s) == 0:
			with self._ifnot():
				pass
		else:
			with self._choice():
				l = [i for i in s.keys()]
				l = sorted(l, reverse=True)
				for i in l:
					with self._option():
						self._token(i)
				with self._ifnot():
					pass

	@graken()
	def _acl_object_group_network_id_(self):
		self.__acl_internal_ids(self.network_groups)

	@graken()
	def _acl_object_network_id_(self):
		self.__acl_internal_ids(self.network_objects)

	@graken()
	def _acl_object_group_service_id_(self):
		self.__acl_internal_ids(self.service_groups)

	@graken()
	def _acl_object_service_id_(self):
		self.__acl_internal_ids(self.service_objects)

	@graken()
	def _acl_object_group_icmp_id_(self):
		self.__acl_internal_ids(self.icmp_groups)

	@graken()
	def _acl_object_group_protocol_id_(self):
		self.__acl_internal_ids(self.protocol_groups)

	@graken()
	def _acl_names_id_(self):
		self.__acl_internal_ids(self.names)

	@graken()
	def _acl_time_range_id_(self):
		self.__acl_internal_ids(self.time_ranges)


