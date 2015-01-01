from acltk.aclObjects import ACLRule, NetworkAny, NetworkAny4, NetworkAny6, ACLRules


class cafBlock:
	def __init__(self, expr):
		assert isinstance(expr, (ACLRule, cafBlock, cafOp))
		self.expr = expr

	def __repr__(self):
		return "{{ {} }}".format(self.expr)

	def run(self, rules, verbose=False):
		assert isinstance(rules, (ACLRules, cafOp, cafBlock)), type(rules)
		if isinstance(self.expr, ACLRule):
			r = rules.filter([self.expr])
			if verbose:
				print("\n{self.__class__.__name__} {self.expr}: {l}".format(self=self, l=len(r)))
			return r
		return self.expr.run(rules, verbose)

	@classmethod
	def parse(cls, filename, text=None, trace=False):
		from acltk.caf import cafParser
		from acltk.cafSemantics import RealCafSemantics
		if not text:
			with open(filename) as f:
				text = f.read()
		parser = cafParser(parseinfo=False, trace_length=200)
		config = parser.parse(
			text,
			"grammar",
			filename=filename,
			trace=trace,
			whitespace=None,
			nameguard=True,
			semantics=RealCafSemantics())
		return config


class cafOp:
	def __init__(self, a, b):
		assert isinstance(a, (cafBlock, cafOp, ACLRule))
		assert isinstance(b, (cafBlock, cafOp, ACLRule))
		def block(n):
			if isinstance(n, ACLRule):
				return cafBlock(n)
			return n
		self.a = block(a)
		self.b = block(b)

	def run(self, rules, verbose=False):
		assert isinstance(rules, (ACLRules, cafOp, cafBlock))

	def result(self, r, verbose=False):
		if verbose:
			print("\n{self.__class__.__name__}\n\t{self.a}\n\t{self.b}: {l}\n".format(self=self, l=len(r)))

	def __repr__(self):
		return "{self.a} {self.__class__.__name__} {self.b}".format(self=self)


class cafOpIntersect(cafOp):
	def run(self, rules, verbose=False):
		cafOp.run(self, rules, verbose)
		a = self.a.run(rules, verbose)
		b = self.b.run(rules, verbose)
		r = a.intersection(b)
		self.result(r, verbose)
		return r


class cafOpUnion(cafOp):
	def run(self, rules, verbose=False):
		cafOp.run(self, rules, verbose)
		a = self.a.run(rules, verbose)
		b = self.b.run(rules, verbose)
		r = a.union(b)
		self.result(r, verbose)
		return r


class cafOpExcept(cafOp):
	def run(self, rules, verbose=False):
		cafOp.run(self, rules, verbose)
		a = self.a.run(rules, verbose)
		b = self.b.run(rules, verbose)
		r = a - b
		self.result(r, verbose)
		return r


class cafNetworkAny(NetworkAny):
	def __init__(self):
		NetworkAny.__init__(self)

	def __and__(self, other):
		if isinstance(other, NetworkAny):
			return True
		return False

	def __repr__(self):
		return "cafNetworkAny"


class cafNetworkAny4(NetworkAny4):
	def __init__(self):
		NetworkAny.__init__(self)

	def __and__(self, other):
		if isinstance(other, NetworkAny4):
			return True
		return False

	def __repr__(self):
		return "cafNetworkAny4"


class cafNetworkAny6(NetworkAny6):
	def __init__(self):
		NetworkAny.__init__(self)

	def __and__(self, other):
		if isinstance(other, NetworkAny6):
			return True
		return False

	def __repr__(self):
		return "cafNetworkAny6"
