from acltk.fwsm import fwsmSemantics as _fwsmSemantics, fwsmParser as _fwsmParser
from acltk.aclSemantics import aclSemantics, aclParser
from acltk.aclObjects import ACLConfig, ACLRule, Names, Name, ACLVersion, InterfaceAccessGroup, ACLNode, NetworkAny, \
	Protocol


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
		if ast.extended is not None:
			return self.access_list_rule_extended(ast)
		else:
			return self.access_list_rule_standard(ast)

	def access_list_rule_extended(self, ast):
		if ast.protocol == 'ethertype':
			return None
		return ACLRule(**ast)

	def access_list_rule_standard(self, ast):
		if ast.protocol == 'ethertype':
			return None

		ast['dest'] = ACLNode(NetworkAny())
		src = ast.source
		del ast['source']
		ast['source'] = ACLNode(src)
		ast['protocol'] = Protocol('ip')
		return ACLRule(**ast)

	def access_group(self, ast):
		if ast.type == 'interface':
			del ast['type']
			return InterfaceAccessGroup(**ast)
		else:
			return None

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

