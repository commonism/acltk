import tatsu.ast
from acltk.aclObjects import ACLConfig, ACLParserOptions, ACLVersion


class pfsenseParserOptions(ACLParserOptions):
	def __init__(self, fetch_urltable=True, **kwargs):
		ACLParserOptions.__init__(self, kwargs)
		self.fetch_urltable = fetch_urltable

class pfsenseConfig(ACLConfig):
	def __init__(self, ast):
		ACLConfig.__init__(self, ast)

	@classmethod
	def _parse(cls, data, filename, options):
		"""

		:rtype : pfsenseConfig
		"""
		from acltk.pfsenseSemantics import pfsenseParser
		parser = pfsenseParser(options)
#		semantics = pfsenseSemantics(parser)
		config = parser.parse(
			data,
			filename=filename,
			trace=options.trace if options else False
		)
		return config

