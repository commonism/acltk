import tatsu.ast
from tatsu.infos import ParserConfig

from acltk.aclObjects import ACLConfig, NetworkAny


class Webtype(NetworkAny):
    def __init__(self, url):
        NetworkAny.__init__(self)
        self.url = url


class fwsmConfig(ACLConfig):
    def __init__(self, ast):
        ACLConfig.__init__(self, ast)

    @classmethod
    def _parse(cls, data, filename, options):
        """

        :rtype : fwsmConfig
        """
        from acltk.fwsmSemantics import fwsmParser, fwsmSemantics

        config = ParserConfig(parseinfo=False, trace_length=200, rule_name="grammar", whitespace="",
            nameguard=True,)
        parser = fwsmParser(config = config)
        semantics = fwsmSemantics(parser)
        config = parser.parse(
            data,
            filename=filename,
            trace=options.trace if options else False,
            colorize=options.trace if options else False,
            semantics=semantics,
        )
        return config
