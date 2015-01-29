import datetime
import ipaddress
import math


class Names:
	def __init__(self):
		self.objects = []

	def add(self, obj):
		assert isinstance(obj, Name)
		self.objects.append(obj)

	def __repr__(self):
		return "names ({})".format(", ".join([repr(i) for i in self.objects]))


class Name:
	def __init__(self, hostname=None, address=None, description=None):
		self.hostname = hostname
		self.address = ipaddress.ip_address(address)
		self.description = description

	def __repr__(self):
		return "Name {self.hostname} -> {self.address}".format(self=self)


class InterfaceAddress:
	def __init__(self, address, netmask, priority=None):
		self.interface = ipaddress.ip_interface("{}/{}".format(address,netmask))
		self.priority = priority


class InterfaceAccessGroup:
	def __init__(self, iface, name, direction):
		self.iface = iface
		self.name = name
		self.direction = direction


class Interface:
	def __init__(self, alias, details):
		self.alias = alias
		self.addresses = []
		self.access_groups = {}
		self.nameif = None
		self.routes = set()
		self.description = None

		for i in details:
			if i.type == 'nameif':
				self.nameif = i.value
			elif i.type == 'description':
				self.description = i.value
			elif i.type[0] == 'ip':
				if i.type[1] == 'address':
					self.addresses.append(InterfaceAddress(*i.value))
				elif i.type[1] == 'access-group':
					self.access_groups[i.value[1]] = InterfaceAccessGroup(self, *i.value)
			elif i.type[0] == 'ipv6':
				if i.type[1] == 'address':
					self.addresses.append(InterfaceAddress(i.value[0], i.value[2]))

	def __repr__(self):
		return "Interface {}".format(self.alias)


class Protocol:
	def __init__(self, p):
		self.name = p

	def __repr__(self):
		return "Protocol {}".format(self.name)


class ProtocolGroup:
	def __init__(self, name, description):
		self.name = name
		self.description = description
		self.objects = []

	def add(self, obj):
		assert isinstance(obj, (Protocol, ProtocolGroup))
		self.objects.append(obj)

	def __repr__(self):
		return "ProtocolGroup {} ({}) # {}".format(self.name, ", ".join([repr(i) for i in self.objects]),
												   self.description)


class ICMP:
	def __init__(self, type, code):
		self.type = type
		self.code = code

	def __repr__(self):
		return "ICMP {} {}".format(self.type, self.code)


class ICMPGroup:
	def __init__(self, name, description):
		self.name = name
		self.description = description
		self.objects = []

	def add(self, obj):
		assert isinstance(obj, (ICMP, ICMPGroup))
		self.objects.append(obj)

	def __repr__(self):
		return "ICMPGroup {} ({}) # {}".format(self.name, ", ".join([repr(i) for i in self.objects]), self.description)


# TODO with target
class NetworkObject:
	def __init__(self, name, description, type=None, address=None, mask=None, start=None, stop=None, fqdn=None, limit=None):
		self.name = name
		self.description = description
		self.type = type
		if type == 'host':
			self.addresses = [NetworkHost(address)]
		elif type == 'subnet':
			self.addresses = [Network(address, mask)]
		elif type == 'range':
			self.addresses = []
			for i in ipaddress.summarize_address_range(
					ipaddress.ip_address(start),
					ipaddress.ip_address(stop)
			):
				self.addresses.append(Network(i.network_address, i.netmask))
		elif type == 'fqdn':
			if limit is None:
				self.addresses = [NetworkAny()]
			elif limit == 'v4':
				self.addresses = [NetworkAny4()]
			elif limit == 'v6':
				self.addresses = [NetworkAny6()]

	def __and__(self, other):
		for i in self.addresses:
			if i & other:
				return True
		return False

	def __repr__(self):
		return "NetworkObject {self.name} {self.type} # {self.description}".format(self=self)


class Network:
	def __init__(self, address, netmask, target=None):
		self.network = ipaddress.ip_network("{}/{}".format(address, netmask), strict=False)
		assert target is None or isinstance(target, Name)
		self.target = target

	def __and__(self, other):
		assert isinstance(other, (Network, NetworkWildcard, NetworkHost, NetworkObject, NetworkGroup, NetworkAny, NetworkAny4, NetworkAny6))
		if isinstance(other, NetworkHost):
			return other.address in self.network
		if isinstance(other, NetworkAny):
			return other & self
		if isinstance(other, NetworkAny4):
			return other & self
		if isinstance(other, NetworkAny6):
			return other & self
		if isinstance(other, Network):
			return self.network.overlaps(other.network) or other.network.overlaps(self.network)
		if isinstance(other, NetworkGroup):
			return other & self
		if isinstance(other, NetworkObject):
			return other & self
		if isinstance(other, NetworkWildcard):
			return other & self

	def __repr__(self):
		return "Network {}".format(str(self.network))


class NetworkWildcard:
	def __init__(self, address, wildcard):
		self.address = ipaddress.ip_address(address)
		self.wildcard = ipaddress.ip_address(wildcard)

	def _addresses(self):
		l = set()
		start = int(self.address) & ~int(self.wildcard)
		bits = int(self.wildcard)

		if start & ~bits == start:
			l.add(ipaddress.ip_address(start))

		todo = [(start, bits)]

		while len(todo):
			addr, bits = todo[0]
			if bits > 0:
				bit = math.floor(math.log(bits, 2))

				if bits == (2**(bit+1)) -1:
					m = ipaddress.ip_network("{}/{}".format(ipaddress.ip_address(addr), 31-bit))
					l.add(m)
				else:
					e = (addr, bits & ~(1 << bit) )
					if bits != e[1]:
						todo.append( e )

					x = addr | (1 << bit)
					e = (x, bits & ~(1 << bit))
					if addr != x or bits != e[1]:
						todo.append( e )
						l.add(ipaddress.ip_address(addr))
						l.add(ipaddress.ip_address(x))
			todo = todo[1:]
		return l

	def __and__(self, other):
		if isinstance(other, NetworkHost):
			return int(other.address) & ~int(self.wildcard) == int(self.address) & ~int(self.wildcard)
		elif isinstance(other, Network):
			return int(other.network.network_address) & ~int(self.wildcard) == \
				   int(self.address) & int(other.network.netmask) & ~int(self.wildcard)
		else:
			return other & self

	def __repr__(self):
		return "NetworkWildcard {}/{}".format(self.address, self.wildcard)


class NetworkAny:
	def __init__(self):
		pass

	def __and__(self, other):
		return True

	def __repr__(self):
		return "NetworkAny"


class NetworkInterface(NetworkAny):
	def __init__(self, name):
		self.name = name

	def __repr__(self):
		return "NetworkInterface {}".format(self.name)


class NetworkAny4:
	version = 4
	def __and__(self, other):
		if isinstance(other, NetworkHost):
			if self.version == other.address.version:
				return True
			else:
				return False
		elif isinstance(other, Network):
			if self.version == other.network.version:
				return True
			else:
				return False
		elif isinstance(other, NetworkWildcard):
			return True
		elif isinstance(other, NetworkAny6):
			return False
		elif isinstance(other, (NetworkAny4, NetworkAny)):
			return True
		else:
			return other & self

	def __repr__(self):
		return "NetworkAny4"


class NetworkAny6:
	version = 6

	def __and__(self, other):
		if isinstance(other, NetworkHost):
			if self.version == other.address.version:
				return True
			else:
				return False
		elif isinstance(other, Network):
			if self.version == other.network.version:
				return True
			else:
				return False
		elif isinstance(other, NetworkWildcard):
			return False
		elif isinstance(other, NetworkAny4):
			return False
		elif isinstance(other, (NetworkAny6, NetworkAny)):
			return True
		else:
			return other & self

	def __repr__(self):
		return "NetworkAny6"


class NetworkHost:
	def __init__(self, address, target=None):
		self.address = ipaddress.ip_address(address)
		assert target is None or isinstance(target, Name)
		self.target = target

	def __and__(self, other):
		if isinstance(other, NetworkHost):
			return self.address == other.address
		else:
			return other & self

	def __repr__(self):
		return "NetworkHost {}".format(str(self.address))


class NetworkGroup:
	def __init__(self, name, description):
		self.name = name
		self.description = description
		self.objects = []

	def add(self, obj):
		assert isinstance(obj, (Network, NetworkGroup, NetworkHost, NetworkObject, NetworkAny, NetworkAny4, NetworkAny6))
		self.objects.append(obj)

	def __and__(self, other):
		for i in self.objects:
			if i & other:
				return True
		return False

	def __repr__(self):
		return "NetworkGroup {} ({}) # {}".format(self.name, ", ".join([repr(i) for i in self.objects]),
												  self.description)


class Service:
	def __init__(self, protocol=None, type=None, source=None, destination=None, icmp_type=None, icmp_code=None):
		assert isinstance(protocol, Protocol)
		self.protocol = protocol
		self.source = source
		self.destination = destination
		self.icmp_type = icmp_type
		self.icmp_code = icmp_code

	def __repr__(self):
		return "Service {self.protocol} src:{self.source} dst:{self.destination}".format(self=self)


class ServiceObject(Service):
	def __init__(self, name, description, **kwargs):
		Service.__init__(self, **kwargs)
		self.name = name
		self.description = description

	def __repr__(self):
		return "ServiceObject {self.name} {self.protocol} src:{self.source} dst:{self.destination} # {self.description}".format(
			self=self)


class ServiceGroup:
	def __init__(self, name, description):
		self.name = name
		self.description = description
		self.objects = []

	def add(self, obj):
		assert isinstance(obj, (Service, ServiceObject, ServiceGroup))
		self.objects.append(obj)

	def __repr__(self):
		return "ServiceGroup {} ({}) # {}".format(self.name, ", ".join([repr(i) for i in self.objects]),
												  self.description)


class Port:
	def __init__(self, op, num):
		self.op = op
		self.num = num

	def __repr__(self):
		return "Port {self.op} {self.num}".format(self=self)


class PortRange:
	def __init__(self, start, stop):
		self.start = start
		self.stop = stop

	def __repr__(self):
		return "PortRange {self.start}:{self.stop}".format(self=self)


class PortGroup:
	def __init__(self, name, protocol, description):
		self.name = name
		self.description = description
		assert isinstance(protocol, Protocol)
		self.protocol = protocol
		self.objects = []

	def add(self, obj):
		assert isinstance(obj, (Port, PortRange, PortGroup))
		self.objects.append(obj)

	def __repr__(self):
		return "PortGroup {} {} ({}) # {}".format(self.name, self.protocol, ", ".join([repr(i) for i in self.objects]),
												  self.description)


class TimeRange:
	def __init__(self, name):
		self.name = name
		self.objects = []

	def add(self, obj):
		assert isinstance(obj, (TimeRangeObjectAbsolute, TimeRangeObjectPeriodic))
		self.objects.append(obj)

	def __repr__(self):
		return "TimeRange {} ({})".format(self.name, ", ".join([repr(i) for i in self.objects]))


class TimeRangeObjectAbsolute:
	def __init__(self, start, end):
		self.start = start
		self.end = end

	def __repr__(self):
		start = end = ""
		if self.start:
			start = self.start.strftime("%H:%M %d %B %Y")
		if self.end:
			end = self.end.strftime("%H:%M %d %B %Y")
		return "Absolute {}-{}".format(start, end)


class TimeRangeObjectPeriodic:
	def __init__(self, stime, sdays, etime, edays):
		self.startTime = stime
		self.startDays = sdays
		self.endTime = etime
		self.endDays = edays

	def __repr__(self):
		sDays = ", ".join(self.startDays)
		sTime = str(self.startTime)

		if self.endDays:
			eDays = self.endDays
		else:
			eDays = ""
		eTime = str(self.endTime)
		return "Periodic {sdays} {stime}-{edays} {etime}".format(sdays=sDays, stime=sTime, edays=eDays, etime=eTime)


class ACLNode:
	def __init__(self, host=None, port=None):
		assert isinstance(host, (Network, NetworkWildcard, NetworkAny, NetworkAny4, NetworkAny6, NetworkGroup, NetworkHost, NetworkObject)), "type {}".format(host)
		self.host = host
		assert port is None or isinstance(port, (Port, PortGroup, PortRange))
		self.port = port

	def __and__(self, other):
		return self.host & other.host

	def __repr__(self):
		if self.port:
			return "ACLNode ({self.host}:{self.port})".format(self=self)
		return "ACLNode ({self.host})".format(self=self)


class ACLRuleOptionLog:
	def __init__(self, args):
		self.options = args


class ACLRuleOptionInActive:
	pass


class ACLRule:
	def __init__(self, line=None, id=None, extended=None, mode=None, protocol=None, source=None, dest=None, remark=None, options=None, icmp=None,
				 **kwargs):
		self.line = line
		self.id = id
		self.extended = extended
		self.mode = mode
		assert protocol is None or isinstance(protocol, (Protocol, ProtocolGroup, Service, ServiceGroup))
		self.protocol = protocol
		assert isinstance(source, ACLNode)
		self.src = source
		assert isinstance(dest, ACLNode)
		self.dst = dest
		self.remark = remark
		if options is None:
			self.options = {}
		else:
			self.options = options
		self.icmp = icmp

	def __and__(self, other):
		assert isinstance(other, ACLRule)
		if self.id and other.id and self.id != other.id:
			return False
		if self.src & other.src and self.dst & other.dst:
			return True
		return False

	def __repr__(self):
		return "ACLRule {self.id} {self.mode} {self.protocol} src:{self.src} {self.dst} # {self.remark}".format(
			self=self)


class ACLObjects:
	def __init__(self):
		self.network = {}
		self.service = {}
		self.port = {}
		self.protocol = {}
		self.time = {}
		self.icmp = {}


class ACLRules:
	def __init__(self):
		self.rules = []

	def add(self, i):
		self.rules.append(i)

	def filter(self, target):
		r = set()
		for acl in self.rules:
			for i in target:
				if i & acl:
					r.add(acl)
					break
		return r


class ACLVersion:
	def __init__(self, v):
		self.version = v


import grako.ast
#from acltk.fwsmObjects import Names


class ACLConfig:
	def __init__(self, ast):
		self.timestamp = datetime.datetime.now()
		self.hostname = ""
		self.domainname = ""
		self.names = Names()
		self.interfaces = {}
		self.objects = ACLObjects()
		self.groups = ACLObjects()
		self.rules = ACLRules()
		self.access_groups = {}
		for i in list(ast):
			if isinstance(i, grako.ast.AST) and 'hostname' in i:
				self.hostname = i.hostname
			elif isinstance(i, grako.ast.AST) and 'domain_name' in i:
				self.domainname = i.domain_name
			elif isinstance(i, ACLRule):
				self.rules.add(i)
			elif isinstance(i, Name):
				self.names.add(i)
			elif isinstance(i, Interface):
				self.interfaces[i.alias] = i
				for k,v in i.access_groups.items():
					self.access_groups[v.name] = v
			elif isinstance(i, TimeRange):
				self.objects.time[i.name] = i
			elif isinstance(i, NetworkObject):
				self.objects.network[i.name] = i
			elif isinstance(i, ServiceObject):
				self.objects.service[i.name] = i
			elif isinstance(i, PortGroup):
				self.groups.port[i.name] = i
			elif isinstance(i, ServiceGroup):
				self.groups.service[i.name] = i
			elif isinstance(i, ProtocolGroup):
				self.groups.protocol[i.name] = i
			elif isinstance(i, ICMPGroup):
				self.groups.icmp[i.name] = i
			elif isinstance(i, NetworkGroup):
				self.groups.network[i.name] = i
			elif isinstance(i, ACLVersion):
				self.version = i.version
			elif isinstance(i, InterfaceAccessGroup):
				for j in self.interfaces.values():
					if j.nameif == i.iface:
						i.iface = j
						j.access_groups[i.direction] = i
						break

				self.access_groups[i.name] = i
			else:
				continue
			ast.remove(i)

	@property
	def name(self):
		return "{}.{}".format(self.hostname, self.domainname)

	@classmethod
	def _parse(cls, data, filename=None, trace=False):
		from acltk.fwsmObjects import fwsmConfig
		from acltk.iosObjects import iosConfig

		for i in [fwsmConfig, iosConfig]:
			try:
				return i._parse(data, filename, trace)
			except Exception:
				print(i)
		raise ValueError("Invalid Config?")

	@classmethod
	def fromString(cls, _data, filename=None, trace=False):
		assert(isinstance(_data, str))
#		data = _data.replace('\r', '')
		data = _data + '\n'
		return cls._parse(data, filename, trace)

	@classmethod
	def fromFile(cls, f, trace=False):
		data = f.read()
		data = data.decode('utf-8-sig')
		return cls.fromString(data, getattr(f, 'name', 'stdin'), trace)


	@classmethod
	def fromPath(cls, path, trace=False):
		with open(path, 'rb') as f:
			return cls.fromFile(f, trace)
		return None

	def resolve(self, r):
		for i in list(r):
			r.add(i.protocol)
			r.add(i.src.host)
			r.add(i.src.port)
			r.add(i.dst.host)
			r.add(i.dst.port)
			r.add(i.id)
			if i.protocol.name in ('icmp','icmp6'):
				if i.icmp:
					r.add(i.icmp)
			for k,v in i.options.items():
				if isinstance(v, TimeRange):
					r.add(v)
			if i.id in self.access_groups:
				r.add(self.access_groups[i.id])

		done = set()
		while True:
			for i in list(r):
				if i in done:
					continue
				else:
					done.add(i)
				if isinstance(i, (NetworkGroup, PortGroup, ServiceGroup, ProtocolGroup, ICMPGroup)):
					r.add(i.__class__.__name__)
					r = r.union(set(i.objects))
					break
				elif isinstance(i, (Network, NetworkHost)):
					if i.target:
						r.add(i.target)
						r.add('Names')
					break
				elif isinstance(i, (NetworkObject, ServiceObject, TimeRange)):
					r.add(i.__class__.__name__)
					break
				elif isinstance(i, InterfaceAccessGroup):
					r.add(i.iface)
					r.add('Interface')
					break
			else:
				break

		return r

	def expand(self):
		todo = [(self.groups.network, NetworkGroup),
			(self.groups.port, PortGroup),
			(self.groups.service, ServiceGroup),
			(self.groups.protocol, ProtocolGroup)]

		for (l,n) in todo:
			for group in l.values():
				while True:
					for obj in group.objects:
						if isinstance(obj, n):
							group.objects.extend(obj.objects)
							group.objects.remove(obj)
							break
					else:
						break

		for group in self.groups.network.values():
			while True:
				for obj in group.objects:
					if isinstance(obj, NetworkObject):
						group.objects.extend(obj.addresses)
						group.objects.remove(obj)
						break
				else:
					break

		for group in self.groups.service.values():
			while True:
				for obj in group.objects:
					if isinstance(obj, ServiceObject):
						group.objects.append(Service(obj.protocol, None, obj.source, obj.destination, obj.icmp_type, obj.icmp_code))
						group.objects.remove(obj)
						break
				else:
					break
