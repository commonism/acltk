from typing import Dict, Union
import ipaddress

from tatsu.parsing import tatsumasu

from acltk.ios import iosSemantics as _iosSemantics, iosParser as _iosParser
from acltk.aclSemantics import aclSemantics, aclParser
from acltk.aclObjects import ACLNode, ACLRules, Network, ACLRule, NetworkHost, Protocol, NetworkAny, NetworkWildcard
from acltk.iosObjects import iosConfig, Route


class iosSemantics(aclSemantics, _iosSemantics):
    def __init__(self, parser):
        aclSemantics.__init__(self, parser)
        _iosSemantics.__init__(self)

    def grammar(self, ast):
        return iosConfig(ast)

    def ios_host(self, ast):
        if ast.wildcard:
            try:
                return Network(ast.address, ast.wildcard)
            except:
                return NetworkWildcard(ast.address, ast.wildcard)
        elif ast.address == "any":
            return NetworkAny()
        else:
            return NetworkHost(ast.address)

    def ios_node(self, ast):
        return ACLNode(ast.host, ast.port)

    def ios_ipv6_host(self, ast):
        if ast.prefix:
            return Network(ast.address, ast.prefix)
        elif ast.address == "any":
            return NetworkAny()
        else:
            return NetworkHost(ast.address)

    def ios_ipv6_node(self, ast):
        return ACLNode(ast.host, ast.port)

    def ip(self, ast):
        return ast.cmd

    def ip_command(self, ast):
        if ast.cmd == "access-list":
            return ast.object
        elif ast.cmd == "domain name":
            ast["domain_name"] = ast.name
            return ast
        elif ast.cmd == "route":
            return ast.route

    def ip_access_list_extended(self, ast):
        if ast.remark:
            remark = []
            for i in ast.remark:
                remark.append(i.remark)
            del ast["remark"]
            ast["remark"] = remark
        return ast

    def ip_access_list_standard(self, ast):
        if ast.remark:
            remark = []
            for i in ast.remark:
                remark.append(i.remark)
            del ast["remark"]
            ast["remark"] = remark
        return ast

    def ip_access_list(self, ast):
        r = ACLRules()
        if ast.type == "extended":
            for obj in ast.objects:
                # 				if obj.protocol.name == "icmp":
                # 					print(ast)
                for i in ["src", "dst"]:
                    if not isinstance(obj[i], ACLNode):
                        x = obj[i]
                        del obj[i]
                        obj[i] = ACLNode(x)
                r.add(ACLRule(extended=ast.type, id=ast.name, **obj))
        elif ast.type == "standard":
            for obj in ast.objects:
                assert not isinstance(obj.src, ACLNode), "unexpected type {} or class {}".format(
                    type(obj.src), obj.src.__class__.__qualname__
                )
                src = ACLNode(host=obj.src)
                r.add(
                    ACLRule(
                        extended=ast.type,
                        id=ast.name,
                        protocol=Protocol("ip"),
                        mode=obj.mode,
                        src=src,
                        dst=ACLNode(NetworkAny()),
                        options=obj.options,
                        remark=obj.remark,
                    )
                )
        return r

    def access_list_ip_standard(self, ast):
        if ast.remark:
            remark = []
            for i in ast.remark:
                remark.append(i.remark)
            del ast["remark"]
            ast["remark"] = remark
        return self.access_list_ip_standard_rule(ast)

    def access_list_ip_standard_rule(self, ast):
        if not isinstance(ast.src, ACLNode):
            src = ACLNode(ast.src)
        else:
            src = ast.src
        return ACLRule(
            protocol=Protocol("ip"),
            dst=ACLNode(NetworkAny()),
            src=src,
            id=ast.id,
            mode=ast.mode,
            remark=ast.remark,
            options=ast.options,
        )

    def access_list_ip_extended(self, ast):
        if ast.remark:
            remark = []
            for i in ast.remark:
                remark.append(i.remark)
            del ast["remark"]
            ast["remark"] = remark
        return self.access_list_ip_extended_rule(ast)

    def access_list_ip_extended_rule(self, ast):
        return ACLRule(
            protocol=ast.protocol,
            dst=ast.dst,
            src=ast.src,
            id=ast.id,
            mode=ast.mode,
            remark=ast.remark,
            icmp=ast.icmp,
            options=ast.options,
        )

    def ipv6(self, ast):
        return ast.cmd

    def ipv6_command(self, ast):
        if ast.cmd == "access-list":
            return ast.object

    def ipv6_access_list(self, ast):
        r = ACLRules()
        for obj in ast.objects:
            for i in ["src", "dst"]:
                if not isinstance(obj[i], ACLNode):
                    x = obj[i]
                    del obj[i]
                    obj[i] = ACLNode(x)
            r.add(ACLRule(extended=ast.type, id=ast.name, **obj))
        return r

    def ipv6_access_list_seq(self, ast):
        ast.rule.options["sequence"] = ast.seq
        return ast.rule

    def ipv6_access_list_rule(self, ast):
        return ast

    def ipv6_access_list_rule_icmp_options(self, ast):
        return self.ipv6_access_list_rule_options(ast)

    def ipv6_access_list_rule_options(self, ast) -> Dict[str, Union[str, int]]:
        return {i.type: i.value for i in ast}

    def ignored(self, ast):
        ast = None
        return None

    def ip_ignored(self, ast):
        ast = None
        return None

    def ip_access_list_extended_rule_options(self, ast):
        r = {}
        for i in ast:
            r[i.type] = i.value
        return r

    def ip_access_list_standard_rule_options(self, ast):
        r = {}
        for i in ast:
            r[i.type] = i.value
        return r

    def ip_route(self, ast):
        if ast.prefix is None:
            return None

        if ast.gw in self.parser.interfaces:
            gw = self.parser.interfaces[ast.gw]
        else:
            gw = ipaddress.ip_address(ast.gw)

        return Route(ipaddress.ip_network(f"{ast.prefix}/{ast.mask}"), gw)

    def delim_start(self, ast):
        self.parser.delim = ast


class iosParser(aclParser, _iosParser):
    def __init__(self, **kwargs):
        aclParser.__init__(self)
        _iosParser.__init__(self, kwargs)
        self.delim = None

    @tatsumasu()
    def _delim_msg_(self):
        if self.delim == "^C":
            # not ^ or ^ not followed by C
            self._pattern(r"([^^]|\^[^C])*")
        else:
            p = r"[^\x{:02x}]*".format(int.from_bytes(self.delim.encode("utf-8"), byteorder="little"))
            self._pattern(p)

    @tatsumasu()
    def _delim_stop_(self):
        if self.delim == "^C":
            self._token("^C")
        else:
            self._pattern(r"\x{:02x}".format(int.from_bytes(self.delim.encode("utf-8"), byteorder="little")))
