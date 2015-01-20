from acltk.aclObjects import ACLConfig, ACLRules, ACLRule


class iosConfig(ACLConfig):
	def __init__(self, ast):
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

		print(self)

	@classmethod
	def parse(cls, filename, text=None, trace=False):
		"""

		:rtype : ACLConfig
		"""
		if not text:
			with open(filename) as f:
				text = f.read()

		from acltk.iosSemantics import iosParser, iosSemantics
		parser = iosParser(parseinfo=False, trace_length=200)
		semantics = iosSemantics(parser)
		config = parser.parse(
			text,
			"grammar",
			filename=filename,
			trace=trace,
			whitespace='',
			nameguard=True,
			semantics=semantics,
			)
		return config
