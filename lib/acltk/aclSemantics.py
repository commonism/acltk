import datetime
import ipaddress

from tatsu.parsing import tatsumasu

from acltk.aclObjects import TimeRangeObjectAbsolute, TimeRangeObjectPeriodic, TimeRange, \
	NetworkObject, ServiceObject, NetworkGroup, PortGroup, ServiceGroup, ProtocolGroup, ICMPGroup, Protocol, ICMP, \
	NetworkHost, Network, Service, PortRange, Port, ACLNode, NetworkAny, Interface, NetworkAny4, NetworkAny6, \
	ACLRuleOptionInActive, ACLRuleOptionLog, NetworkInterface, ACLVersion, NATObject, NATMapped, NATMappedSource, NATMappedSourceFallback, NATMappedDestination, NATReal, NATRealNode, Name
import tatsu.ast


class aclSemantics:
	def __init__(self, parser):
		self.parser = parser

	def _learn(self, name, obj):
		self.parser._learn(name, obj)

	def NL(self, ast):
		return None

	def SP(self, ast):
		return None

	def WS(self, ast):
		return None

	def version(self, ast):
		return ACLVersion(ast.version)

	def interface(self, ast):
		iface = Interface(ast.alias, ast.detail)
		if ast.alias is not None:
			self._learn(ast.alias, iface)
		if iface.nameif is not None:
			self._learn(iface.nameif, iface)
		return iface

	def interface_detail(self, ast):
		if ast.type is None:
			return None
		return ast

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
		assert (ast.type in frozenset(['no', 'absolute', 'periodic'])), "time-range type {} is not known".format(ast.type)
		if ast.type == 'no':
			return None
		elif ast.type == 'absolute':
			return TimeRangeObjectAbsolute(ast.start, ast.end)
		elif ast.type == 'periodic':
			return TimeRangeObjectPeriodic(ast.start, ast.days, ast.end, ast.edays)


	def time_range(self, ast):
		t = TimeRange(ast.name)
		self._learn(ast.name, t)
		for i in ast.objects:
			t.add(i)
		return t

	def object_type(self, ast):
		action = {
			'network': (NetworkObject, self.parser.network_objects),
			'service': (ServiceObject, self.parser.service_objects),
		}
		nat = None

		if ast.args is None:
			del ast['args']
			ast['args'] = {}

		# NAT - specified single line item with the object - default
		if 'nat' in ast.args:
			nat = ast.args.nat
			del ast.args['nat']


		cls, groups = action[ast.type]
		p = cls(ast.name, ast.description, **ast['args'])


		# NAT - specified with the initial object definition
		# simplifies testing -
		if nat is None and 'nat' in ast:
			nat = ast.nat

		if ast.name not in groups:
			self._learn(ast.name, p)

		if nat:
			nat.real.src.node = p
			setattr(p, 'nat', nat)


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

		# only tcp & udp can be of type Protocol
		# everything else, e.g. "icmp-type" definitions are of type str
		assert isinstance(ast.type, (str, Protocol)), "unknown type {}".format(type(ast.type))
		if isinstance(ast.type, str):
			cls, groups = action[ast.type]
		elif isinstance(ast.type, Protocol):
			cls, groups = action[ast.type.name]


		p = cls(ast.name, ast.description)
		#groups[ast.name] = p
		self._learn(ast.name, p)
		for i in ast.objects:
			p.add(i)
		return p

	def ip4(self, ast):
		return ipaddress.ip_address(ast)

	def ip6(self, ast):
		return ipaddress.ip_address(ast)

	def _resolve_addr(self, addr):
		if isinstance(addr, ipaddress._BaseAddress):
			return addr, None
		elif isinstance(addr, Name):
			return addr.address, addr
		raise ValueError(addr)

	def protocol_icmp(self, ast):
		return Protocol(ast)

	def protocol_tcp_udp(self, ast):
		return Protocol(ast)

	def protocol_code(self, ast):
		return Protocol(ast)

	def protocol_int(self, ast):
		assert (0 <= int(ast) <= 255), "invalid protocol {}".format(ast)
		return Protocol(ast)

	def port_int(self, ast):
		assert (0 <= int(ast) <= 2**16-1), "invalid port {}".format(ast)
		return ast

	def icmp_type_int(self, ast):
		assert (0 <= int(ast) <= 2**8-1), "invalid icmp type {}".format(ast)
		return ast

	def icmp_code_int(self, ast):
		assert (0 <= int(ast) <= 2**8-1), "invalid icmp code {}".format(ast)
		return ast

	def network_group_object(self, ast):
		assert (ast.type is not None), "object type is None"
		if ast.type == 'network-object':
			if ast.name == 'object':
				return ast.object

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
			return ast.group

	def service_group_object(self, ast):
		assert (ast.type is not None), "object type is None"
		if ast.type == 'service-object':
			if ast.protocol == 'object':
				return ast.object
			else:
				assert isinstance(ast.protocol, Protocol), "protocol {} is unknown".format(ast.protocol)
				for i in frozenset(['type', 'object','group']) & set(ast.keys()):
					del ast[i]
				return Service(**ast)
		elif ast.type == 'group-object':
			return ast.group

	def service_object(self, ast):
		assert (isinstance(ast['protocol'], Protocol)), "invalid protocol {}".format(ast.protocol)
		return ast

	def service_object_source(self, ast):
		return ast

	def service_object_destination(self, ast):
		return ast

	def service_object_op(self, ast):
		if ast[0] == 'range':
			return PortRange(ast[1], ast[2])
		else:
			return Port(ast[0], ast[1])

	def port_group_object(self, ast):
		assert (ast is not None), "object is None"
		if ast[0] == 'port-object':
			if ast[1] == 'range':
				return PortRange(ast[2], ast[3])
			else:
				return Port(ast[1], ast[2])
		elif ast[0] == 'group-object':
			return ast[1]

	def protocol_group_object(self, ast):
		assert (ast.type is not None), "object type is None"
		if ast.type == 'protocol-object':
			return Protocol(ast.name)
		elif ast.type == 'group-object':
			return ast.group

	def icmp_group_object(self, ast):
		assert (ast.type is not None), "object type is None"
		if ast.type == 'icmp-object':
			return ICMP(ast.name, None)
		elif ast.type == 'group-object':
			return ast.group

	def acl_protocol(self, ast):
		if ast.type == 'object':
			return ast.object
		elif ast.type == 'object-group':
			return ast.group
		elif ast.type == 'name':
			assert isinstance(ast.name, Protocol), "invalid type {}".format(type(ast.name))
			return ast.name
		raise ValueError(ast)

	def acl_host(self, ast):
		if ast.type == 'host' or ast.type == 'ip':
			addr, target = self._resolve_addr(ast.address)
			return NetworkHost(addr, target=target)
		elif ast.type == 'interface':
			return NetworkInterface(ast.name)
		elif ast.type in ('any', 'any4', 'any6'):
			return {'any':NetworkAny(),'any4':NetworkAny4(), 'any6':NetworkAny6()}[ast.type]
		elif ast.type == 'object':
			return ast.object
		elif ast.type == 'object-group':
			return ast.group
		elif ast.type == 'network':
			addr, target = self._resolve_addr(ast.address)
			return Network(addr, ast.netmask, target=target)
		raise ValueError(ast.type)

	def acl_port(self, ast):
		if ast.type == 'range':
			return PortRange(ast.start, ast.stop)
		elif ast.type == 'object-group':
			return ast.group
		elif ast.type == 'port':
			return Port(ast.op, ast.port)
		raise ValueError(ast.type)

	def acl_icmp_node(self, ast):
		return ACLNode(ast, None)

	def acl_icmp_options(self, ast):
		if ast.type is None:
			return None
		if ast.type == 'object-group':
			return ast.group
		else:
			return ICMP(ast.type, ast.code)

	def node(self, ast):
		return ACLNode(ast.host, ast.port)

	def acl_options(self, ast):
		r = {}
		for i in ast:
			assert (i.type is None or i.type in frozenset(['log','time-range','inactive'])), "option {} is unknown".format(i.type)
			if i.type is None:
				continue
			elif i.type == 'log':
				r[i.type] = ACLRuleOptionLog(i.options)
			elif i.type == 'time-range':
				r[i.type] = i.option
			elif i.type == 'inactive':
				r[i.type] = ACLRuleOptionInActive()
		return r

	def acl_name(self, ast):
		return ast

	def acl_name_ws(self, ast):
		return self.parser.names[ast.name]

	def acl_name_slash(self, ast):
		return self.parser.names[ast.name]

	def acl_interface(self, ast):
		return self.parser.interfaces[ast.name]

	def acl_time_range(self, ast):
		return self.parser.time_ranges[ast.name]

	def acl_object_group_icmp(self, ast):
		return self.parser.icmp_groups[ast.name]

	def acl_object_group_network(self, ast):
		return self.parser.network_groups[ast.name]

	def acl_object_group_port(self, ast):
		return self.parser.port_groups[ast.name]

	def acl_object_group_protocol(self, ast):
		return self.parser.protocol_groups[ast.name]

	def acl_object_group_service(self, ast):
		return self.parser.service_groups[ast.name]

	def acl_object_network(self, ast):
		return self.parser.network_objects[ast.name]

	def acl_object_service(self, ast):
		return self.parser.service_objects[ast.name]

	def network_nat_mapped(self, ast):
		# mapped src
		mapped = ast
		type = mapped['type']
		value = mapped[mapped['type']]
		if type == 'object' or type == 'group':
			src = mapped['object']
		elif type == 'address':
			if mapped['mask'] is None:
				src = NetworkHost(value)
			else:
				src = Network(value, mapped['mask'])
		elif type == 'interface':
			src = 'interface'
		elif type == 'pool':
			src = value['range']
		else:
			raise ValueError(ast['type'])

		return NATMappedSource('dummy',src, ast.fallback)

	def network_object_nat(self, ast):
		real = {}
		mapped = {}
		service = None
		options = {'auto': True}

		# iface
		real['iface'] = ast['iface']['real']
		mapped['iface'] = ast['iface']['mapped']

		# mapped src
		real['dst'] = mapped['dst'] = NetworkAny()
		real['src'] = mapped['src'] = ast['mapped'].node

		if mapped['src'] == 'interface':
			mapped['src'] = NetworkInterface(mapped['iface'].nameif or mapped['iface'].alias)

		fallback = ast['mapped'].fallback

		if fallback and fallback.interface == 'interface':
			fallback.interface = mapped['src'] if isinstance(mapped['src'], NetworkInterface) else NetworkInterface(mapped['iface'].nameif or mapped['iface'].alias)

		if ast.service is not None:
			if ast.service == 'dns':
				options['dns'] = True
			elif isinstance(ast.service, Service):
				real['service'] = Service(ast.service.protocol, None, ast.service.dst)
				mapped['service'] = Service(ast.service.protocol, None, ast.service.src)
			else:
				raise ValueError(ast.service)

		for i in ast.options:
			options[i] = True

		r = NATObject(NATReal(real['iface'],
							  NATRealNode(real['src']),
							  NATRealNode(real['dst']),
							  mapped.get('service', None)
					),
					  NATMapped(mapped['iface'],
								NATMappedSource(ast.type, mapped['src'], fallback),
								NATMappedDestination(mapped['dst']),
								mapped.get('service',None)), options=options)

		return r
#		return None

	def network_object_nat_service(self, ast):
		if ast.type == 'dns':
			return "dns"
		elif ast.type == 'service':
			return Service(Protocol(ast.protocol), ast.real, ast.mapped)

	def nat_mapped_fallback(self, ast):
		return NATMappedSourceFallback(ast.interface, ast.ipv6)

	def nat_interfaces(self, ast):
		# NAT Interface name can be "any" - well … have the interface
		r = {}
		for k,v in {'real':ast.real, 'mapped':ast.mapped}.items():
			if v == 'any':
				r[k] = Interface('any', [])
			else:
				r[k] = self.parser.interfaces[v]

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
		self.interfaces = dict()

		self.objects = dict()

	def _learn(self, name, obj):
		{
			NetworkGroup:self.network_groups,
			NetworkObject:self.network_objects,
			ServiceGroup:self.service_groups,
			ServiceObject:self.service_objects,
			PortGroup:self.port_groups,
			ICMPGroup:self.icmp_groups,
			ProtocolGroup:self.protocol_groups,
			Name:self.names,
			TimeRange:self.time_ranges,
			Interface:self.interfaces
		}[obj.__class__][name] = obj
		self.objects[name] = obj

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

	@tatsumasu()
	def _acl_interface_id_(self):
		self.__acl_internal_ids(self.interfaces)

	@tatsumasu()
	def _acl_object_group_network_id_(self):
		self.__acl_internal_ids(self.network_groups)

	@tatsumasu()
	def _acl_object_network_id_(self):
		self.__acl_internal_ids(self.network_objects)

	@tatsumasu()
	def _acl_object_group_service_id_(self):
		self.__acl_internal_ids(self.service_groups)

	@tatsumasu()
	def _acl_object_group_port_id_(self):
		self.__acl_internal_ids(self.port_groups)


	@tatsumasu()
	def _acl_object_service_id_(self):
		self.__acl_internal_ids(self.service_objects)

	@tatsumasu()
	def _acl_object_group_icmp_id_(self):
		self.__acl_internal_ids(self.icmp_groups)

	@tatsumasu()
	def _acl_object_group_protocol_id_(self):
		self.__acl_internal_ids(self.protocol_groups)

	@tatsumasu()
	def _acl_names_id_(self):
		self.__acl_internal_ids(self.names)

	@tatsumasu()
	def _acl_time_range_id_(self):
		self.__acl_internal_ids(self.time_ranges)


