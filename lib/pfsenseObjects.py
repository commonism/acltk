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

