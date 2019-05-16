from acltk.aclObjects import ACLRule, NetworkAny, NetworkAny4, NetworkAny6, ACLRules, NATObject


class cafBlock:
	def __init__(self, expr):
		assert isinstance(expr, (ACLRule, cafBlock, cafOp)), "unexpected type {} or class {}".format(type(expr), expr.__class__.__qualname__)
		self.expr = expr

	def __repr__(self):
		return "{{ {} }}".format(self.expr)

	def run(self, rules, verbose=False):
		assert isinstance(rules, (ACLRules, cafOp, cafBlock)), "unexpected type {} or class {}".format(type(rules), rules.__class__.__qualname__)
		if isinstance(self.expr, ACLRule):
			r = rules.filter([self.expr])
			if verbose:
				print("\n{self.__class__.__name__} {self.expr}: {l}".format(self=self, l=len(r)))
			return r
		return self.expr.run(rules, verbose)

	@classmethod
	def _parse(cls, data, filename=None, trace=False):
		from acltk.caf import cafParser
		from acltk.cafSemantics import RealCafSemantics
		parser = cafParser(parseinfo=False, trace_length=200)
		config = parser.parse(
			data,
			"grammar",
			filename=filename,
			trace=trace,
			colorize=trace,
			whitespace=None,
			nameguard=True,
			semantics=RealCafSemantics())
		return config

	@classmethod
	def fromString(cls, _data, filename=None, trace=False):
		assert (isinstance(_data, str)), "unexpected type {} or class {}".format(type(_data), _data.__class__.__qualname__)
		return cls._parse(_data, filename, trace)

	@classmethod
	def fromFile(cls, f, trace=False):
		data = f.read()
		data = data.decode('utf-8-sig')
		return cls.fromString(data, getattr(f, 'name', 'stdin'), trace)


	@classmethod
	def fromPath(cls, path, trace=False):
		with open(path, 'rb') as f:
			return cls.fromFile(f, trace)
		return None



class cafOp:
	def __init__(self, a, b):
		assert isinstance(a, (cafBlock, cafOp, ACLRule)), "unexpected type {} or class {}".format(type(a), a.__class__.__qualname__)
		assert isinstance(b, (cafBlock, cafOp, ACLRule)), "unexpected type {} or class {}".format(type(b), b.__class__.__qualname__)
		def block(n):
			if isinstance(n, ACLRule):
				return cafBlock(n)
			return n
		self.a = block(a)
		self.b = block(b)

	def run(self, rules, verbose=False):
		assert isinstance(rules, (ACLRules, cafOp, cafBlock, NATObject)), "unexpected type {} or class {}".format(type(rules), rules.__class__.__qualname__)

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
