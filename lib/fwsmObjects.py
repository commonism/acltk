import tatsu.ast
from acltk.aclObjects import ACLConfig, NetworkAny

class Webtype(NetworkAny):
	def __init__(self, url):
		NetworkAny.__init__(self)
		self.url = url

class fwsmConfig(ACLConfig):
	def __init__(self, ast):
		ACLConfig.__init__(self, ast)

	@classmethod
	def _parse(cls, data, filename=None, trace=False):
		"""

		:rtype : fwsmConfig
		"""
		from acltk.fwsmSemantics import fwsmParser, fwsmSemantics
		parser = fwsmParser(parseinfo=False)
		semantics = fwsmSemantics(parser)
		config = parser.parse(
			data,
			"grammar",
			filename=filename,
			trace=trace,
			colorize=trace,
			whitespace='',
			nameguard=True,
			semantics=semantics)
		return config
