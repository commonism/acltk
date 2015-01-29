import ipaddress
from acltk.aclObjects import ACLConfig, ACLRules, ACLRule, Interface


class Route:
	def __init__(self, network, gw):
		assert isinstance(network, ipaddress.IPv4Network)
		assert isinstance(gw, (ipaddress.IPv4Address, Interface)), "unexpected type {}".format(type(gw))
		self.network = network
		self.gw = gw

class iosConfig(ACLConfig):
	def __init__(self, ast):
		self.routes = []
		rules = list(filter(lambda x: isinstance(x, (ACLRule, ACLRules)),ast))
		ACLConfig.__init__(self, ast)
		self.rules.rules = []
		for i in rules:
			if isinstance(i, ACLRules):
				self.rules.rules.extend(i.rules)
			elif isinstance(i, ACLRule):
				self.rules.add(i)
			else:
				print(i)
				continue

		for i in ast:
			if isinstance(i, ACLRules):
				continue
			elif isinstance(i, Route):
				self.routes.append(i)

		for r in self.routes:
			if isinstance(r.gw, Interface):
				r.gw.routes.add(r)
			else:
				for iface in self.interfaces.values():
					for ifaddr in iface.addresses:
						if r.gw in ifaddr.interface.network:
							iface.routes.add(r)

	@classmethod
	def _parse(cls, data, filename=None, trace=False):
		"""

		:rtype : ACLConfig
		"""
		from acltk.iosSemantics import iosParser, iosSemantics
		parser = iosParser(parseinfo=False, trace_length=200)
		semantics = iosSemantics(parser)
		config = parser.parse(
			data,
			"grammar",
			filename=filename,
			trace=trace,
			whitespace='',
			nameguard=True,
			semantics=semantics,
			)
		return config
