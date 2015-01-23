import grako.ast
from acltk.aclObjects import ACLConfig, ACLVersion

class fwsmConfig(ACLConfig):
	def __init__(self, ast):
		ACLConfig.__init__(self, ast)

	@classmethod
	def parse(cls, filename, text=None, trace=False):
		"""

		:rtype : fwsmConfig
		"""
		if not text:
			with open(filename, 'rb') as f:
				text = f.read()
				text = text.decode('utf-8-sig')

		from acltk.fwsmSemantics import fwsmParser, fwsmSemantics
		parser = fwsmParser(parseinfo=False)
		semantics = fwsmSemantics(parser)
		config = parser.parse(
			text,
			"grammar",
			filename=filename,
			trace=trace,
			whitespace='',
			nameguard=True,
			semantics=semantics)
		return config
