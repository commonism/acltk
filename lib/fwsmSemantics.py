from acltk.fwsm import fwsmSemantics as _fwsmSemantics, fwsmParser as _fwsmParser
from acltk.aclSemantics import aclSemantics, aclParser
from acltk.aclObjects import ACLConfig, ACLRule, Names, Name


class fwsmSemantics(aclSemantics, _fwsmSemantics):
	def __init__(self, parser):
		aclSemantics.__init__(self, parser)
		_fwsmSemantics.__init__(self)

	def names(self, ast):
		n = Names()
		for i in ast.objects:
			n.add(i)
		return n

	def name(self, ast):
		n = Name(**ast)
		self.parser.names[ast.hostname] = n
		return n


	def access_list(self, ast):
		if ast.remark:
			remark = ""
			for i in ast['remark']:
				remark += i['remark']
			del ast['remark']
			ast['remark'] = remark
		return self.access_list_rule(ast)

	def access_list_rule(self, ast):
		if ast.protocol == 'ethertype':
			return None
		return ACLRule(**ast)

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

