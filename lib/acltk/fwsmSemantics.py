from acltk.fwsm import fwsmSemantics as _fwsmSemantics, fwsmParser as _fwsmParser
from acltk.aclSemantics import aclSemantics, aclParser
from acltk.aclObjects import ACLConfig, ACLRule, Names, Name, ACLVersion, InterfaceAccessGroup, ACLNode, NetworkAny, \
	Protocol, NATObject, NATMapped, NATMappedSource, NATMappedSourceFallback, NATMappedDestination, NATReal, NATRealNode, NetworkInterface
from acltk.fwsmObjects import Webtype

class fwsmSemantics(aclSemantics, _fwsmSemantics):
	def __init__(self, parser):
		aclSemantics.__init__(self, parser)
		_fwsmSemantics.__init__(self)

	def name(self, ast):
		n = Name(**ast)
		self.parser.names[ast.hostname] = n
		return n

	def access_list(self, ast):
		if ast.remark:
			remark = []
			for i in ast.remark:
				remark.append(i.remark)
			del ast['remark']
			ast['remark'] = remark

		assert (ast.extended is not None and ast.extended in frozenset(['extended', 'standard', 'webtype', 'ethertype'])), "unexpected value {}".format(ast.type)
		if ast.extended == 'extended':
			return self.access_list_rule_extended(ast)
		elif ast.extended == 'standard':
			return self.access_list_rule_standard(ast)
		elif ast.extended == 'webtype':
			return self.access_list_rule_webtype(ast)
		elif ast.extended == 'ethertype':
			return None



	def access_list_rule_extended(self, ast):
		return ACLRule(**ast)

	def access_list_rule_standard(self, ast):
		ast['dst'] = ACLNode(NetworkAny())
		src = ast.src
		del ast['src']
		ast['src'] = ACLNode(src)
		ast['protocol'] = Protocol('ip')
		return ACLRule(**ast)

	def access_list_rule_webtype(self, ast):
		ast['src'] = ACLNode(NetworkAny())
		if ast.protocol == 'tcp':
			pass
		elif ast.protocol == 'url':
			ast['dst'] = ACLNode(Webtype(ast.url))
		else:
			raise ValueError(ast.protocol)
		protocol = ast.protocol
		del ast['protocol']
		ast['protocol'] = Protocol(protocol)
		return ACLRule(**ast)

	def access_group(self, ast):
		if ast.type == 'interface':
			del ast['type']
			return InterfaceAccessGroup(**ast)
		else:
			return None

	def nat(self, ast):
		real = {}
		mapped = {}
		options = {}
		description = None

		# fwsm/PIX NAT syntax is not supported
		if ast.iface is None:
			return None

		if ast.service:
			if ast.src['mapped'].type == 'static':
				# For source port translation, the objects must specify the source service.
				# The order of the service objects in the command for source port translation is service real_obj mapped_obj.
				if ast.service[1].src and not ast.service[2].dst and ast.service[2].src and not ast.service[2].dst:
					real['service'] = ast.service[1]
					mapped['service'] = ast.service[2]
				# For destination port translation, the objects must specify the destination service.
				# The order of the service objects for destination port translation is service mapped_obj real_obj.
				elif not ast.service[1].src and ast.service[2].dst and not ast.service[2].src and ast.service[2].dst:
					mapped['service'] = ast.service[1]
					real['service'] = ast.service[2]
				# In the rare case where you specify both the source and destination ports in the object,
				# the first service object contains the real source port / mapped destination port;
				# the second service object contains the mapped source port / real destination port.
				elif ast.service[1].src and ast.service[2].dst and ast.service[2].src and ast.service[2].dst:
					raise ValueError("not yet")
				else:
					raise ValueError("unexpected")
				# For identity port translation, simply use the same service object for both the real and mapped ports (source and / or destination ports, depending on your configuration).
			elif ast.src['mapped'].type == 'dynamic':
				real['service'] = ast.service[1]
				mapped['service'] = ast.service[2]
			else:
				raise ValueError(ast.src['mapped'].type)

		for i in ast.options:
			if i.type == 'description':
				description = i.value
			else:
				options[i.type] = True

		for i in ['src','dst', 'iface']:
			obj = ast.get(i, None)
			if obj is None:
				real[i] = mapped[i] = None
			else:
				real[i] = obj.get('real', None)
				mapped[i]= obj.get('mapped', None)

		# src or dst is "interface" - lookup the interface and replace
		for k,i in {'real':real,'mapped':mapped}.items():
			ifname = i['iface'].nameif or i['iface'].alias
			if i['src'] and i['src'].node == 'interface':
				i['src'].node = NetworkInterface(ifname)
			if i['dst'] and i['dst'].node == 'interface':
				i['dst'].node = NetworkInterface(ifname)

		if mapped['src'] and getattr(mapped['src'], 'fallback', None):
			ifname = mapped['iface'].nameif or mapped['iface'].alias
			mapped['src'].fallback.interface = NetworkInterface(ifname)


		if ast.pos: # and ast.pos[0] == 'after-auto':
			options['after-auto'] = True

		r = NATObject(NATReal(real['iface'],
								  real['src'],
								  real['dst'],
								  real.get('service', None)
								  ),
					  NATMapped(mapped['iface'],
									mapped['src'],
									mapped['dst'],
									mapped.get('service', None)
									),
					  description,
					  options)
		return r

	def nat_real_node(self, ast):
		if ast.type == 'any':
			return NetworkAny()
		elif ast.type in ('object','group'):
			return ast.node
		else:
			return ValueError()

	def nat_src(self, ast):
		obj = ast.mapped
		mapped = None
		fallback = None

		if obj.type == 'object':
			mapped = obj.name
		elif obj.type == 'interface':
			mapped = 'interface'
		elif obj.type == 'pool':
			mapped = obj.pool.range
		elif obj.type == 'any':
			mapped = NetworkAny()
		elif obj.type == 'group':
			mapped = obj.name
		else:
			raise ValueError(obj.type)

		return {'real': NATRealNode(ast['real']), 'mapped': NATMappedSource(ast['type'], mapped, obj.fallback)}

	def nat_dst(self, ast):
		mapped = None
		obj = ast.mapped
		if obj.type == 'object':
			mapped = obj.name
		elif obj.type == 'group':
			mapped = obj.name
		elif obj.type == 'interface':
			mapped = 'interface'
		elif obj.type == 'pool':
			mapped = obj.pool
		elif obj.type == 'any':
			mapped = NetworkAny()
		else:
			raise ValueError(obj.type)

		return {'real':NATRealNode(ast['real']), 'mapped':NATMappedDestination(mapped)}


	def grammar(self, ast):
		# pdb.set_trace()
		return ACLConfig(ast)

	def ignored(self, ast):
		ast = None
		return None


class fwsmParser(aclParser, _fwsmParser):
	def __init__(self, parseinfo):
		aclParser.__init__(self)
		_fwsmParser.__init__(self, parseinfo=parseinfo)

