from grako.exceptions import FailedSemantics
from acltk.aclObjects import ACLRule, Network, NetworkHost, NetworkAny, NetworkGroup, ACLNode, NetworkAny4, NetworkAny6
from acltk.cafObjects import cafOpUnion, cafBlock, cafNetworkAny, cafNetworkAny4, cafNetworkAny6, cafOpIntersect, \
    cafOpExcept
from acltk.caf import cafSemantics


class RealCafSemantics(cafSemantics):
    def __init__(self):
        cafSemantics.__init__(self)

    def network(self, ast):
        if ast.address == 'any':
            return NetworkAny()
        elif ast.address == 'any4':
            return NetworkAny4()
        elif ast.address == 'any6':
            return NetworkAny6()
        elif ast.address == 'ANY':
            return cafNetworkAny()
        elif ast.address == 'ANY4':
            return cafNetworkAny4()
        elif ast.address == 'ANY6':
            return cafNetworkAny6()
        if ast.netmask is None:
            return NetworkHost(ast.address)
        return Network(ast.address, ast.netmask)

    def expr(self, ast):
        if isinstance(ast, (ACLRule, cafBlock)):
            return ast
        else:
            while True:
                for i, item in enumerate(ast):
                    if (i + 1) % 2 != 0:
                        continue
                    a = ast[i - 1]
                    b = ast[i + 1]

                    if item == 'intersect':
                        ast[i] = cafOpIntersect(a, b)
                        del ast[i + 1]
                        del ast[i - 1]
                        break
                else:
                    break

            while True:
                for i, item in enumerate(ast):
                    if (i + 1) % 2 != 0:
                        continue

                    if item in ('union', 'except'):
                        a = ast[i - 1]
                        b = ast[i + 1]

                        if item == 'union':
                            ast[i] = cafOpUnion(a, b)
                        elif item == 'except':
                            ast[i] = cafOpExcept(a, b)
                        del ast[i + 1]
                        del ast[i - 1]
                        break
                else:
                    break

        return ast[0]

    def expr_r(self, ast):
        r = [ast[0]]
        r.extend(ast[1])
        return r

    def set_expr(self, ast):
        return cafBlock(ast[1])

    def net(self, ast):
        if len(ast.object) == 1:
            return ast.object[0]
        n = NetworkGroup('', '')
        for network in ast.object:
            n.add(network)
        return n

    def set_id(self, ast):
        return ast[1]

    def set(self, ast):
        if len(ast.objects) == 1 and isinstance(ast.objects[0], cafBlock):
            return ast.objects[0]
        ip = []
        for i in ast.objects:
            if 'ip' in i:
                ip.extend(i.ip)

        nodes = {'src': NetworkGroup('src', ''),
                 'dst': NetworkGroup('dst', '')}

        for i in ip:
            nodes[i[0]].add(i[1])

        for k, v in nodes.items():
            if len(v.objects) == 0:
                nodes[k] = NetworkAny()
            elif len(v.objects) == 1:
                nodes[k] = v.objects[0]

        return ACLRule(id=ast.id, source=ACLNode(nodes['src']), dest=ACLNode(nodes['dst']))

    def comment(self, ast):
        return None

    def grammar(self, ast):
        return cafBlock(ast)
