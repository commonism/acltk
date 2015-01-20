from grako.parsing import graken

from acltk.ios import iosSemantics as _iosSemantics, iosParser as _iosParser
from acltk.aclSemantics import aclSemantics, aclParser
from acltk.aclObjects import ACLNode, ACLRules, Network, ACLRule, NetworkHost, Protocol, NetworkAny, NetworkWildcard
from acltk.iosObjects import iosConfig


class iosSemantics(aclSemantics, _iosSemantics):
	def __init__(self, parser):
		aclSemantics.__init__(self, parser)
		_iosSemantics.__init__(self)

	def grammar(self, ast):
		return iosConfig(ast)

	def ios_host(self, ast):
		if ast.wildcard:
			try:
				return Network(ast.address, ast.wildcard)
			except:
				return NetworkWildcard(ast.address, ast.wildcard)
		elif ast.address == 'any':
			return NetworkAny()
		else:
			return NetworkHost(ast.address)

	def ios_node(self, ast):
		return ACLNode(ast.host, ast.port)

	def ip(self, ast):
		return ast.cmd

	def ip_command(self, ast):
		if ast.cmd == 'access-list':
			return ast.object
		elif ast.cmd == 'domain name':
			ast['domain_name'] = ast.name
			return ast

	def ip_access_list_extended(self, ast):
		if ast.remark:
			remark = ""
			for i in ast.remark:
				remark += i.remark
			del ast['remark']
			ast['remark'] = remark
		return ast

	def ip_access_list_standard(self, ast):
		if ast.remark:
			remark = ""
			for i in ast.remark:
				remark += i.remark
			del ast['remark']
			ast['remark'] = remark
		return ast

	def ip_access_list(self, ast):
		r = ACLRules()
		if ast.type == 'extended':
			for obj in ast.objects:
				if obj.protocol.name == "icmp":
					print(ast)
				for i in ["source","dest"]:
					if not isinstance(obj[i], ACLNode):
						x = obj[i]
						del obj[i]
						obj[i] = ACLNode(x)
				r.add(ACLRule(extended=ast.type, id=ast.name, **obj))
		elif ast.type == 'standard':
			for obj in ast.objects:
				if not isinstance(obj.source, ACLNode):
					src = ACLNode(host=obj.source)
				else:
					src = src
				r.add(ACLRule(extended=ast.type, id=ast.name, protocol=Protocol("ip"), mode=obj.mode, source=src, dest=ACLNode(NetworkAny()), options=obj.options, remark=obj.remark))
		return r

	def access_list_ip_standard(self, ast):
		if ast.remark:
			remark = ""
			for i in ast['remark']:
				remark += i['remark']
			del ast['remark']
			ast['remark'] = remark
		return self.access_list_ip_standard_rule(ast)

	def access_list_ip_standard_rule(self, ast):
		if not isinstance(ast.source, ACLNode):
			src = ACLNode(ast.source)
		else:
			src = ast.source
		return ACLRule(protocol=Protocol('ip'), dest=ACLNode(NetworkAny()), source=src, id=ast.id, mode=ast.mode, remark=ast.remark, options=ast.options)

	def access_list_ip_extended(self, ast):
		if ast.remark:
			remark = ""
			for i in ast['remark']:
				remark += i['remark']
			del ast['remark']
			ast['remark'] = remark
		return self.access_list_ip_extended_rule(ast)

	def access_list_ip_extended_rule(self, ast):
		return ACLRule(protocol=ast.protocol, dest=ast.dest, source=ast.source, id=ast.id, mode=ast.mode, remark=ast.remark, icmp=ast.icmp, options=ast.options)

	def ignored(self, ast):
		ast = None
		return None

	def ip_ignored(self, ast):
		ast = None
		return None

	def ip_access_list_extended_rule_options(self, ast):
		r = {}
		for i in ast:
			r[i.type] = i.value
		return r

	def ip_access_list_standard_rule_options(self, ast):
		r = {}
		for i in ast:
			r[i.type] = i.value
		return r

class iosParser(aclParser, _iosParser):
	def __init__(self, **kwargs):
		aclParser.__init__(self)
		_iosParser.__init__(self, kwargs)

