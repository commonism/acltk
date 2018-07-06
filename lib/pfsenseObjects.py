import tatsu.ast
from acltk.aclObjects import ACLConfig, ACLVersion

class pfsenseConfig(ACLConfig):
	def __init__(self, ast):
		ACLConfig.__init__(self, ast)

	@classmethod
	def _parse(cls, data, filename=None, trace=False):
		"""

		:rtype : pfsenseConfig
		"""
		from acltk.pfsenseSemantics import pfsenseParser
		parser = pfsenseParser()
#		semantics = pfsenseSemantics(parser)
		config = parser.parse(
			data,
			filename=filename,
			trace=trace
		)
		return config



class ACLSeparator:
	def __init__(self, iface, rule, text, bg):
		self.iface = iface
		self.rule = rule
		self.text = text
		self.bg = bg
	def __repr__(self):
		return "ACLSeparator {s.iface} {s.rule} {s.text}".format(s=self)