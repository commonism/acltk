import collections
import datetime
import ipaddress
import math
import fnmatch
import logging
import socket
import itertools

log = logging.getLogger()


def nstrsum(x):
    # 	return sum([ord(v) * 2 ** idx for idx, v in enumerate(x)])
    return sum([(ord(v) - 255) * 2**idx for idx, v in enumerate(x)])


class Names:
    def __init__(self):
        self.objects = []

    def add(self, obj):
        assert isinstance(obj, Name), f"unexpected type {type(obj)} or class {obj.__class__.__qualname__}"
        self.objects.append(obj)

    def __repr__(self):
        return "names ({})".format(", ".join([repr(i) for i in self.objects]))


class Name:
    def __init__(self, hostname=None, address=None, description=None):
        self.hostname = hostname
        self.address = ipaddress.ip_address(address)
        self.description = description

    def __repr__(self):
        return "Name {self.hostname} -> {self.address}".format(self=self)


class InterfaceAddress:
    def __init__(self, address, netmask, priority=None):
        self.interface = ipaddress.ip_interface(f"{address}/{netmask}")
        self.priority = priority


class InterfaceAccessGroup:
    def __init__(self, iface, name, direction):
        self.iface = iface
        self.name = name
        self.direction = direction

class Switchport:
    def __init__(self):
        self.mode = ""
        self.access: VLAN | None = None
        self.trunk: VLANs | None = None

class Interface:
    def __init__(self, alias, details):
        self.alias = alias
        self.addresses = []
        self.access_groups = {}
        self.nameif = None
        self.routes = set()
        self.description = None
        self.switchport : Switchport | None = None

        for i in details:
            if i is None:  # no [ip address|...]
                continue
            if i.type == "nameif":
                self.nameif = i.value
            elif i.type == "description":
                self.description = i.value
            elif i.type == "switchport":
                if self.switchport is None:
                    self.switchport = Switchport()
                if i.value["type"] == "mode":
                    self.switchport.mode = i.value["mode"]
                elif i.value["type"] == "trunk":
                    if (op:=i.value["value"]["op"]) == "set":
                        self.switchport.trunk = i.value["value"]["vlans"]
                    elif op == "add":
                        self.switchport.trunk.items.extend(i.value["value"]["vlans"].items)
            elif i.type[0] == "ip":
                if i.type[2] == "address":
                    self.addresses.append(InterfaceAddress(i.value[0], i.value[2]))
                elif i.type[2] == "access-group":
                    self.access_groups[f"{i.type[0]}-{i.value[2]}"] = InterfaceAccessGroup(self, i.value[0], i.value[2])
            elif i.type[0] == "ipv6":
                if i.type[2] == "address":
                    if isinstance(i.value, list):
                        self.addresses.append(InterfaceAddress(i.value[0], i.value[2]))
                    else:
                        self.addresses.append(InterfaceAddress(i.value, "128"))
                elif i.type[2] == "traffic-filter":
                    self.access_groups[f"{i.type[0]}-{i.value[2]}"] = InterfaceAccessGroup(self, i.value[0], i.value[2])


    def __repr__(self):
        return f"Interface {self.alias}"


class VLAN:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return f"VLAN {self.value}"

class VLANRange:
    def __init__(self, start, end):
        self.start = start
        self.end = end

    def __repr__(self):
        return f"VLANRange {self.start}-{self.end}"

class VLANs:
    def __init__(self, items):
        assert all((isinstance(obj, (VLAN, VLANRange)) for obj in items))
        self.items = items

    def __repr__(self):
        return f"VLANS {self.items}"


class NATReal:
    def __init__(self, iface, src, dst, service=None):
        self.iface = NetworkInterface(iface.nameif or iface.alias)
        self.src = src
        self.dst = dst
        self.service = service

    def __repr__(self):
        return "{i.iface}::{i.src}::{i.dst}".format(i=self)


class NATRealNode:
    def __init__(self, node):
        self.node = node


class NATMappedSource:
    def __init__(self, _type, node, fallback=None):
        assert (
            node is None
            or isinstance(node, (NetworkHost, Network, NetworkAny, NetworkObject, NetworkInterface, NetworkGroup))
            or node == "interface"
        ), f"unexpected type {type(node)} or class {node.__class__.__qualname__} {node}"

        self.type = _type
        self.node = node
        self.fallback = fallback


class NATMappedDestination:
    def __init__(self, node):
        assert (
            node is None
            or isinstance(node, (NetworkAny, NetworkObject, NetworkInterface, NetworkGroup))
            or node == "interface"
        ), f"unexpected type {type(node)} or class {node.__class__.__qualname__} {node}"

        self.node = node


class NATMapped:
    def __init__(self, iface, src, dst, service=None):
        self.iface = NetworkInterface(iface.nameif or iface.alias)
        assert src is None or isinstance(src, NATMappedSource), "unexpected type {} or class {}".format(
            type(src), src.__class__.__qualname__
        )
        self.src = src
        assert dst is None or isinstance(dst, NATMappedDestination), "unexpected type {} or class {}".format(
            type(dst), dst.__class__.__qualname__
        )
        self.dst = dst

        self.service = service

    def __repr__(self):
        return "{i.iface}::{i.src}::{i.dst}".format(i=self)


class NATMappedSourceFallback:
    def __init__(self, interface=None, ipv6=False):
        self.interface = interface
        self.ipv6 = ipv6


class NATObject:
    def __init__(self, real, mapped, description=None, options=None):
        assert real is None or isinstance(real, NATReal), "unexpected type {} or class {}".format(
            type(real), real.__class__.__qualname__
        )
        assert mapped is None or isinstance(mapped, NATMapped), "unexpected type {} or class {}".format(
            type(mapped), mapped.__class__.__qualname__
        )

        self.real = real
        self.mapped = mapped

        self.description = description
        self.options = {} if options is None else options

    def __and__(self, other):
        assert isinstance(other, ACLRule), "unexpected type {} or class {}".format(
            type(other), other.__class__.__qualname__
        )

        for i in ["real", "mapped"]:
            rm = getattr(self, i)
            src = ACLNode(rm.src.node) if rm.src and rm.src.node else None
            dst = ACLNode(rm.dst.node) if rm.dst and rm.dst.node else None

            if src and dst:
                if other.src & src and other.dst & dst:
                    return True
            elif src:
                if other.src & src:
                    return True
            elif dst:
                if other.dst & dst:
                    return True

        return False

    def __repr__(self):
        return f"<NATObject {self.real} -> {self.mapped}"


class _Group:
    _allowed = None.__class__

    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.objects = []

    def add(self, obj):
        assert isinstance(obj, self._allowed) or isinstance(
            obj, self.__class__
        ), f"unexpected type {type(obj)} or class {obj.__class__.__qualname__}"
        self.objects.append(obj)

    def _expand(self):

        def expand_r(l):
            r = []
            for obj in l:
                if isinstance(obj, self.__class__):
                    r.extend(expand_r(obj.objects))
                else:
                    r.append(obj)
            return r

        return expand_r(self.objects)

    def expand(self, insitu=True):
        """
        Expand the _Group - resolve all _Groups and use their objects

        :param insitu: True - replace objects with expanded objects
        False - create new _Group with expanded objects
        :return: the _Group with the expanded objects
        :rtype: _Group
        """
        if insitu:
            self.objects = self._expand()
            return self
        else:
            obj = self.__class__(self.name, self.description)
            obj.objects = self._expand()
            obj.expand()
            return obj

    def sort(self, insitu=True):
        raise NotImplementedError(f"not implemented for {self.__class__.__qualname__}")


class Protocol:
    def __init__(self, p):
        self.name = p

    def __repr__(self):
        return f"Protocol {self.name}"

    def __iter__(self):
        return [self.name].__iter__()


class ProtocolGroup(_Group):
    _allowed = Protocol

    def __init__(self, name, description):
        _Group.__init__(self, name, description)

    @staticmethod
    def key_of(o):
        if isinstance(o, Protocol):
            try:
                return int(o.name)
            except ValueError:
                return nstrsum(o.name)
        elif isinstance(o, ProtocolGroup):
            return nstrsum(o.name)
        else:
            raise ValueError(f"unsortable {o.__class__.__qualname__}")

    def sort(self, insitu=True):
        if insitu:
            obj = self
        else:
            obj = self.collapse(insitu=False)

        obj.objects = sorted(self.objects, key=ProtocolGroup.key_of)

        return obj

    def __repr__(self):
        return "ProtocolGroup {} ({}) # {}".format(
            self.name, ", ".join([repr(i) for i in self.objects]), self.description
        )


class ICMP:
    def __init__(self, type, code):
        self.type = type
        self.code = code

    def __repr__(self):
        return f"ICMP {self.type} {self.code}"


class ICMPGroup(_Group):
    _allowed = ICMP

    def __init__(self, name, description):
        _Group.__init__(self, name, description)

    def __repr__(self):
        return "ICMPGroup {} ({}) # {}".format(self.name, ", ".join([repr(i) for i in self.objects]), self.description)


# TODO with target
class NetworkObject:
    def __init__(
        self, name, description, type=None, address=None, mask=None, start=None, stop=None, fqdn=None, limit=None
    ):
        self.name = name
        self.description = description
        self.type = type
        if type is None:
            self.addresses = []
        elif type == "nat":
            self.addresses = []
        elif type == "host":
            self.addresses = [NetworkHost(address)]
        elif type == "subnet":
            self.addresses = [Network(address, mask)]
        elif type == "range":
            self.addresses = []
            for i in ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(stop)):
                self.addresses.append(Network(i.network_address, i.prefixlen))
        elif type == "fqdn":
            if limit is None:
                self.addresses = [NetworkAny()]
            elif limit == "v4":
                self.addresses = [NetworkAny4()]
            elif limit == "v6":
                self.addresses = [NetworkAny6()]
        else:
            raise ValueError(type)

    def __and__(self, other):
        for i in self.addresses:
            if i & other:
                return True
        return False

    def __repr__(self):
        return "NetworkObject {self.name} {self.type} # {self.description}".format(self=self)


class Network:
    def __init__(self, address, netmask, target=None):
        self.network = ipaddress.ip_network(f"{address}/{netmask}", strict=False)
        assert target is None or isinstance(target, Name), "unexpected type {} or class {}".format(
            type(target), target.__class__.__qualname__
        )
        self.target = target

    def __and__(self, other):
        assert isinstance(
            other,
            (
                Network,
                NetworkWildcard,
                NetworkHost,
                NetworkObject,
                NetworkGroup,
                NetworkAny,
                NetworkAny4,
                NetworkAny6,
                NetworkInterface,
            ),
        ), f"unexpected type {type(other)} or class {other.__class__.__qualname__}"
        if isinstance(other, NetworkHost):
            return other.address in self.network
        if isinstance(other, NetworkAny):
            return other & self
        if isinstance(other, NetworkAny4):
            return other & self
        if isinstance(other, NetworkAny6):
            return other & self
        if isinstance(other, Network):
            return self.network.overlaps(other.network) or other.network.overlaps(self.network)
        if isinstance(other, NetworkGroup):
            return other & self
        if isinstance(other, NetworkObject):
            return other & self
        if isinstance(other, NetworkWildcard):
            return other & self
        if isinstance(other, NetworkInterface):
            return other & self

    def __repr__(self):
        return f"Network {str(self.network)}"


class NetworkWildcard:
    def __init__(self, address, wildcard):
        self.address = ipaddress.ip_address(address)
        self.wildcard = ipaddress.ip_address(wildcard)

    def _addresses(self):
        l = set()
        start = int(self.address) & ~int(self.wildcard)
        wild = int(self.wildcard)

        if start & ~wild == start:
            l.add(ipaddress.ip_address(start))

        todo = [(start, wild)]

        while len(todo):
            # basically ... iterates over all bits of the wildcard
            addr0, wild0 = todo[0]
            if wild0 > 0:
                bit = math.floor(math.log(wild0, 2))

                if wild0 == (2 ** (bit + 1)) - 1:
                    # the mask is a inverted netmask
                    # e.g. 0.0.0.255
                    m = ipaddress.ip_network(f"{ipaddress.ip_address(addr0)}/{31 - bit}")
                    l.add(m)
                else:
                    # the mask has zeroes after ones
                    # e.g. 0.0.1.0 and is not a inverted netmask

                    # iterate
                    addr1, wild1 = (addr0 | (1 << bit), wild0 & ~(1 << bit))

                    if wild0 != wild1:
                        todo.append((addr0, wild1))

                    if (addr0, wild0) != (addr1, wild1):
                        todo.append((addr1, wild1))
                        l.add(ipaddress.ip_address(addr0))
                        l.add(ipaddress.ip_address(addr1))
            todo = todo[1:]
        return l

    def __and__(self, other):
        if isinstance(other, NetworkHost):
            return int(other.address) & ~int(self.wildcard) == int(self.address) & ~int(self.wildcard)
        elif isinstance(other, Network):
            return int(other.network.network_address) & ~int(self.wildcard) == int(self.address) & int(
                other.network.netmask
            ) & ~int(self.wildcard)
        else:
            return other & self

    def __repr__(self):
        return f"NetworkWildcard {self.address}/{self.wildcard}"


class NetworkAny:
    def __init__(self):
        pass

    def __and__(self, other):
        return True

    def __repr__(self):
        return "NetworkAny"


class NetworkInterface:
    def __init__(self, name):
        self.name = name

    def __and__(self, other):
        return True

    def __repr__(self):
        return f"NetworkInterface {self.name}"


class NetworkAny4:
    version = 4

    def __and__(self, other):
        if isinstance(other, NetworkHost):
            if self.version == other.address.version:
                return True
            else:
                return False
        elif isinstance(other, Network):
            if self.version == other.network.version:
                return True
            else:
                return False
        elif isinstance(other, NetworkWildcard):
            return True
        elif isinstance(other, NetworkAny6):
            return False
        elif isinstance(other, (NetworkAny4, NetworkAny)):
            return True
        else:
            return other & self

    def __repr__(self):
        return "NetworkAny4"


class NetworkAny6:
    version = 6

    def __and__(self, other):
        if isinstance(other, NetworkHost):
            if self.version == other.address.version:
                return True
            else:
                return False
        elif isinstance(other, Network):
            if self.version == other.network.version:
                return True
            else:
                return False
        elif isinstance(other, NetworkWildcard):
            return False
        elif isinstance(other, NetworkAny4):
            return False
        elif isinstance(other, (NetworkAny6, NetworkAny)):
            return True
        else:
            return other & self

    def __repr__(self):
        return "NetworkAny6"


class NetworkHost:
    def __init__(self, address, target=None):
        self.address = ipaddress.ip_address(address)
        assert target is None or isinstance(target, Name), "unexpected type {} or class {}".format(
            type(target), target.__class__.__qualname__
        )
        self.target = target

    def __and__(self, other):
        if isinstance(other, NetworkHost):
            return self.address == other.address
        else:
            return other & self

    def __repr__(self):
        return f"NetworkHost {str(self.address)}"


class NetworkGroup(_Group):
    _allowed = (Network, NetworkHost, NetworkObject, NetworkAny, NetworkAny4, NetworkAny6)

    def __init__(self, name, description):
        _Group.__init__(self, name, description)

    def expand(self, insitu=True):
        ng = super().expand(insitu)

        # replace NetworkObjects with addresses
        n = []
        for obj in ng.objects:
            if isinstance(obj, NetworkObject):
                n.extend(obj.addresses)
            else:
                n.append(obj)
        ng.objects = n
        return ng

    def collapse(self, insitu=True):
        """
        Collapse the NetworkGroups Addresses

        :param insitu: True - in place, modify this object
        False - create new object

        :return: collapsed NetworkGroup
        """
        # expansion required?
        if any(filter(lambda o: not isinstance(o, (Network, NetworkObject)), self.objects)):
            if insitu:
                raise ValueError("expansion required")
            obj = self.expand(insitu)
        else:
            obj = self
        return obj._collapse()

    def _collapse(self):
        # FIXME - remove NetworkAny
        if any(filter(lambda o: isinstance(o, (NetworkAny, NetworkAny4, NetworkAny6)), self.objects)):
            self.objects = list(
                filter(lambda o: not isinstance(o, (NetworkAny, NetworkAny4, NetworkAny6)), self.objects)
            )

        # NetworkGroup is assumed to be expanded, contains only Network and NetworkHost
        addresses = [
            {Network: lambda x: x.network, NetworkHost: lambda x: x.address}[h.__class__](h) for h in self.objects
        ]

        self.objects.clear()

        for h in ipaddress.collapse_addresses(addresses):
            if not isinstance(h, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                raise ValueError(f"unexpected type {h}")
            if h.num_addresses > 1:
                h_ = Network(h.network_address, h.netmask)
            else:
                h_ = NetworkHost(h.network_address)
            self.add(h_)
        return self

    @staticmethod
    def key_of(o):
        if isinstance(o, Network):
            return int(o.network.network_address)
        elif isinstance(o, NetworkHost):
            return int(o.address)
        elif isinstance(o, NetworkGroup):
            return nstrsum(o.name)
        elif isinstance(o, (NetworkAny, NetworkAny4, NetworkAny6)):
            return nstrsum(o.__class__.__name__)
        elif isinstance(o, NetworkObject):
            return nstrsum(o.name)
        else:
            raise ValueError(f"unsortable {o.__class__.__qualname__}")

    def sort(self, insitu=True):
        if insitu:
            obj = self
        else:
            obj = self.collapse(insitu=False)

        obj.objects = sorted(self.objects, key=NetworkGroup.key_of)

        return obj

    def __and__(self, other):
        for i in self.objects:
            if i & other:
                return True
        return False

    def __repr__(self):
        return "NetworkGroup {} ({}) # {}".format(
            self.name, ", ".join([repr(i) for i in self.objects]), self.description
        )


class Service:
    def __init__(self, protocol=None, src=None, dst=None, icmp_type=None, icmp_code=None, **kwargs):
        assert isinstance(protocol, Protocol), "unexpected type {} or class {}".format(
            type(protocol), protocol.__class__.__qualname__
        )
        assert len(kwargs.keys()) == 0 or set(kwargs.keys()) == {"type"}, f"unexpected kwargs {kwargs.keys()}"
        self.protocol = protocol
        self.src = src
        self.dst = dst
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code

    def __repr__(self):
        return "Service {self.protocol} src:{self.src} dst:{self.dst}".format(self=self)


class ServiceObject(Service):
    def __init__(self, name, description, **kwargs):
        Service.__init__(self, **kwargs)
        self.name = name
        self.description = description

    def __repr__(self):
        return "ServiceObject {self.name} {self.protocol} src:{self.src} dst:{self.dst} # {self.description}".format(
            self=self
        )


class ServiceGroup(_Group):
    _allowed = (Service, ServiceObject)

    def __init__(self, name, description):
        _Group.__init__(self, name, description)

    @staticmethod
    def key_of(o):
        if isinstance(o, (Service, ServiceObject)):
            return (
                o.protocol.name,
                PortGroup.key_of(o.src) if o.src else 0,
                PortGroup.key_of(o.dst) if o.dst else 0,
                o.icmp_code or "",
                o.icmp_type or "",
            )
        elif isinstance(o, Protocol):
            return (o.name, 0, 0, "", "")
        elif isinstance(o, ServiceGroup):
            return (o.name, 0, 0, "", "")
        else:
            raise ValueError(f"unsortable {o.__class__.__qualname__} {o}")

    def sort(self, insitu=True):
        if insitu:
            obj = self
        else:
            obj = self.collapse(insitu=False)

        obj.objects = sorted(self.objects, key=ServiceGroup.key_of)
        return obj

    def expand(self, insitu=True):
        sg = super().expand(insitu)

        # replace ServiceObject with Service
        n = []
        for obj in sg.objects:
            if isinstance(obj, ServiceObject):
                n.append(Service(obj.protocol, obj.src, obj.dst, obj.icmp_type, obj.icmp_code))
            else:
                n.append(obj)
        sg.objects = n
        return sg

    def __repr__(self):
        return "ServiceGroup {} ({}) # {}".format(
            self.name, ", ".join([repr(i) for i in self.objects]), self.description
        )


class PortUtil:
    _servnames = """
	aol			|	TCP      	|	5190 	|	America Online
	bgp			|	TCP      	|	179  	|	Border Gateway Protocol, RFC 1163
	biff			|	UDP      	|	512  	|	Used by mail system to notify users that new mail is received
	bootpc			|	UDP      	|	68   	|	Bootstrap Protocol Client
	bootps			|	UDP      	|	67   	|	Bootstrap Protocol Server
	chargen			|	TCP      	|	19   	|	Character Generator
	citrix-ica		|	TCP      	|	1494 	|	Citrix Independent Computing Architecture (ICA) protocol
	cmd			|	TCP      	|	514  	|	Similar to exec except that cmd has automatic authentication
	ctiqbe			|	TCP      	|	2748 	|	Computer Telephony Interface Quick Buffer Encoding
	daytime			|	TCP      	|	13   	|	Day time, RFC 867
	discard			|	TCP,UDP  	|	9    	|	Discard
	domain			|	TCP,UDP  	|	53   	|	DNS
	dnsix			|	UDP      	|	195  	|	DNSIX Session Management Module Audit Redirector
	echo			|	TCP,UDP  	|	7    	|	Echo
	exec			|	TCP      	|	512  	|	Remote process execution
	finger			|	TCP      	|	79   	|	Finger
	ftp			|	TCP      	|	21   	|	File Transfer Protocol (control port)
	ftp-data		|	TCP      	|	20   	|	File Transfer Protocol (data port)
	gopher			|	TCP      	|	70   	|	Gopher
	https			|	TCP      	|	443  	|	HTTP over SSL
	h323              	|	TCP      	|	1720 	|	H.323 call signalling
	hostname          	|	TCP      	|	101  	|	NIC Host Name Server
	ident             	|	TCP      	|	113  	|	Ident authentication service
	imap4             	|	TCP      	|	143  	|	Internet Message Access Protocol, version 4
	irc               	|	TCP      	|	194  	|	Internet Relay Chat protocol
	isakmp            	|	UDP      	|	500  	|	Internet Security Association and Key Management Protocol
	kerberos          	|	TCP,UDP  	|	750  	|	Kerberos
	klogin            	|	TCP      	|	543  	|	KLOGIN
	kshell            	|	TCP      	|	544  	|	Korn Shell
	ldap              	|	TCP      	|	389  	|	Lightweight Directory Access Protocol
	ldaps             	|	TCP      	|	636  	|	Lightweight Directory Access Protocol (SSL)
	lpd               	|	TCP      	|	515  	|	Line Printer Daemon - printer spooler
	login             	|	TCP      	|	513  	|	Remote login
	lotusnotes        	|	TCP      	|	1352 	|	IBM Lotus Notes
	mobile-ip         	|	UDP      	|	434  	|	MobileIP-Agent
	nameserver        	|	UDP      	|	42   	|	Host Name Server
	netbios-ns        	|	UDP      	|	137  	|	NetBIOS Name Service
	netbios-dgm       	|	UDP      	|	138  	|	NetBIOS Datagram Service
	netbios-ssn       	|	TCP      	|	139  	|	NetBIOS Session Service
	nntp              	|	TCP      	|	119  	|	Network News Transfer Protocol
	ntp               	|	UDP      	|	123  	|	Network Time Protocol
	pcanywhere-status 	|	UDP      	|	5632 	|	pcAnywhere status
	pcanywhere-data   	|	TCP      	|	5631 	|	pcAnywhere data
	pim-auto-rp       	|	TCP,UDP  	|	496  	|	Protocol Independent Multicast, reverse path flooding, dense mode
	pop2              	|	TCP      	|	109  	|	Post Office Protocol - Version 2
	pop3              	|	TCP      	|	110  	|	Post Office Protocol - Version 3
	pptp              	|	TCP      	|	1723 	|	Point-to-Point Tunneling Protocol
	radius            	|	UDP      	|	1645 	|	Remote Authentication Dial-In User Service
	radius-acct       	|	UDP      	|	1646 	|	Remote Authentication Dial-In User Service (accounting)
	rip               	|	UDP      	|	520  	|	Routing Information Protocol
	secureid-udp      	|	UDP      	|	5510 	|	SecureID over UDP
	smtp              	|	TCP      	|	25   	|	Simple Mail Transport Protocol
	snmp              	|	UDP      	|	161  	|	Simple Network Management Protocol
	snmptrap          	|	UDP      	|	162  	|	Simple Network Management Protocol - Trap
	sqlnet       		|	TCP      	|	1521 	|	Structured Query Language Network
	ssh          		|	TCP      	|	22   	|	Secure Shell
	sunrpc (rpc) 		|	TCP,UDP  	|	111  	|	Sun Remote Procedure Call
	syslog       		|	UDP      	|	514  	|	System Log
	tacacs       		|	TCP,UDP  	|	49   	|	Terminal Access Controller Access Control System Plus
	talk         		|	TCP,UDP  	|	517  	|	Talk
	telnet       		|	TCP      	|	23   	|	RFC 854 Telnet
	tftp         		|	UDP      	|	69   	|	Trivial File Transfer Protocol
	time         		|	UDP      	|	37   	|	Time
	uucp         		|	TCP      	|	540  	|	UNIX-to-UNIX Copy Program
	who          		|	UDP      	|	513  	|	Who
	whois        		|	TCP      	|	43   	|	Who Is
	www          		|	TCP      	|	80  	|	World Wide Web
	xdmcp        		|	UDP      	|	177  	|	X Display Manager Control Protocol
	echo			|	ICMP		|	8	|
	echo-reply		| 	ICMP 		| 	0 	|
	information-reply 	| 	ICMP 		| 	16 	|
	information-request	| 	ICMP 		| 	15 	|
	mask-reply		| 	ICMP 		|  	18 	|
	mask-request 		| 	ICMP		|  	17 	|
	mobile-redirect 	| 	ICMP		|  	32 	|
	parameter-problem 	|	ICMP		|  	12 	|
	redirect		|	ICMP		|  	5 	|
	router-advertisement	|	ICMP		|  	9 	|
	router-solicitation	|	ICMP		|  	10 	|
	source-quench		|	ICMP		|  	4 	|
	time-exceeded		|	ICMP		|  	11 	|
	timestamp-reply 	|	ICMP		|  	14 	|
	timestamp-request 	|	ICMP		|  	13 	|
	unreachable 		|	ICMP		|  	3 	|
	traceroute		|	ICMP		| 	30	|
	"""
    _serv = collections.namedtuple("serv", field_names=["name", "protocol", "port", "description"])

    @classmethod
    def getservbyname(cls, name, proto=None):
        for s in cls.services():
            if s.name == name and (proto is None or proto.toupper() == s.protocol):
                return int(s.port)
        return None

    @classmethod
    def services(cls):
        for line in cls._servnames.split("\n"):
            line = line.strip()
            if not line:
                continue
            name, protocol, port, description = map(lambda x: x.strip(), line.split("|"))
            for p in protocol.split(","):
                yield cls._serv(name.split(" ")[0], p, int(port), description)


from functools import total_ordering


@total_ordering
class Port:
    def __init__(self, op, num):
        self.op = op
        self.num = num

    def __repr__(self):
        return "Port {self.op} {self.num}".format(self=self)

    def __eq__(self, o):
        if o is None:
            c = ("", -1)
        else:
            c = (o.op or "", o.num)
        return (self.op or "", self.num) == c

    def __ne__(self, o):
        return not self == o

    def __lt__(self, o):
        if o is None:
            c = ("", -1)
        else:
            c = (o.op or "", o.num)

        return (self.op or "", self.num) < c

    def __hash__(self):
        return id(self)


class PortRange:
    def __init__(self, start, stop):
        try:
            int(start)
            int(stop)
            assert start < stop, "last Port must be greater than first"
        except ValueError:
            pass
        self.start = start
        self.stop = stop

    def __repr__(self):
        return "PortRange {self.start}:{self.stop}".format(self=self)


class PortGroup(_Group):
    _allowed = (Port, PortRange)

    def __init__(self, name, protocol, description):
        _Group.__init__(self, name, description)
        assert isinstance(protocol, Protocol), "unexpected type {} or class {}".format(
            type(protocol), protocol.__class__.__qualname__
        )
        self.protocol = protocol

    def expand(self, insitu=True):
        if insitu:
            self.objects = self._expand()
            return self
        else:
            obj = self.__class__(self.name, self.protocol, self.description)
            obj.objects = self._expand()
            return obj

    @staticmethod
    def key_of(o):
        def _key(x):
            try:
                return int(x)
            except ValueError:
                pass
            try:
                return socket.getservbyname(x)
            except OSError:
                pass
            return nstrsum(x)

        if isinstance(o, Port):
            return _key(o.num)
        elif isinstance(o, PortRange):
            return _key(o.start)
        elif isinstance(o, PortGroup):
            return nstrsum(o.name)
        else:
            raise ValueError(f"can not compare {type(o)}")

    def sort(self, insitu=True):
        if insitu:
            obj = self
        else:
            obj = self.expand(insitu=False)

        obj.objects = sorted(obj.objects, key=PortGroup.key_of)
        return obj

    def __repr__(self):
        return "PortGroup {} {} ({}) # {}".format(
            self.name, self.protocol, ", ".join([repr(i) for i in self.objects]), self.description
        )


class TimeRange:
    def __init__(self, name):
        self.name = name
        self.objects = []

    def add(self, obj):
        assert isinstance(
            obj, (TimeRangeObjectAbsolute, TimeRangeObjectPeriodic)
        ), f"unexpected type {type(obj)} or class {obj.__class__.__qualname__}"
        self.objects.append(obj)

    def __repr__(self):
        return "TimeRange {} ({})".format(self.name, ", ".join([repr(i) for i in self.objects]))


class TimeRangeObjectAbsolute:
    def __init__(self, start, end):
        self.start = start
        self.end = end

    def __repr__(self):
        start = end = ""
        if self.start:
            start = self.start.strftime("%H:%M %d %B %Y")
        if self.end:
            end = self.end.strftime("%H:%M %d %B %Y")
        return f"Absolute {start}-{end}"


class TimeRangeObjectPeriodic:
    def __init__(self, stime, sdays, etime, edays):
        self.startTime = stime
        self.startDays = sdays
        self.endTime = etime
        self.endDays = edays

    def __repr__(self):
        sDays = ", ".join(self.startDays)
        sTime = str(self.startTime)

        if self.endDays:
            eDays = self.endDays
        else:
            eDays = ""
        eTime = str(self.endTime)
        return f"Periodic {sDays} {sTime}-{eDays} {eTime}"


class ACLNode:
    def __init__(self, host=None, port=None):
        assert isinstance(
            host,
            (
                Network,
                NetworkWildcard,
                NetworkAny,
                NetworkAny4,
                NetworkAny6,
                NetworkGroup,
                NetworkHost,
                NetworkObject,
                NetworkInterface,
            ),
        ), f"unexpected type {type(host)} or class {host.__class__.__qualname__}"
        self.host = host
        assert port is None or isinstance(port, (Port, PortGroup, PortRange)), "unexpected type {} or class {}".format(
            type(port), port.__class__.__qualname__
        )
        self.port = port

    def __and__(self, other):
        return self.host & other.host

    def __repr__(self):
        if self.port:
            return "ACLNode ({self.host}:{self.port})".format(self=self)
        return f"ACLNode ({self.host})"


class ACLRuleOptionLog:
    def __init__(self, args):
        self.options = args


class ACLRuleOptionInActive:
    pass


class ACLRuleOptionInterface:
    def __init__(self, interfaces, direction):
        self.interfaces = interfaces
        self.direction = direction


class ACLRule:
    def __init__(
        self,
        line=None,
        id=None,
        extended=None,
        mode=None,
        protocol=None,
        src=None,
        dst=None,
        remark=None,
        options=None,
        icmp=None,
        head=None,
        **kwargs,
    ):
        self.line = line
        self.id = id
        self.extended = extended
        self.mode = mode
        assert protocol is None or isinstance(
            protocol, (Protocol, ProtocolGroup, Service, ServiceGroup)
        ), f"unexpected type {type(protocol)} or class {protocol.__class__.__qualname__}"
        self.protocol = protocol
        assert isinstance(src, ACLNode), f"unexpected type {type(src)} or class {src.__class__.__qualname__}"
        self.src = src
        assert isinstance(dst, ACLNode), f"unexpected type {type(dst)} or class {dst.__class__.__qualname__}"
        self.dst = dst
        self.remark = remark if remark else []
        if options is None:
            self.options = {}
        else:
            self.options = options
        self.icmp = icmp
        self.head = head

    def __and__(self, other):
        assert isinstance(other, (ACLRule, NATObject)), "unexpected type {} or class {}".format(
            type(other), other.__class__.__qualname__
        )
        if isinstance(other, NATObject):
            # FIXME abuse
            return other & self
        if self.id and other.id:
            pattern = name = None
            if self.id[0] == self.id[-1] == "/":
                pattern = self.id[1:-1]
                name = other.id
            elif other.id[0] == other.id[-1] == "/":
                pattern = other.id[1:-1]
                name = self.id

            if name and pattern:
                if not fnmatch.fnmatchcase(name, pattern):
                    return False
            elif self.id != other.id:
                return False

        if not (self.src & other.src and self.dst & other.dst):
            return False

        return True

    def __repr__(self):
        return "ACLRule {self.id} {self.mode} {self.protocol} src:{self.src} dst:{self.dst} # {self.remark}".format(
            self=self
        )


class ACLCaption:
    def __init__(self, text, bg):
        self.text = text
        self.bg = bg

    def __repr__(self):
        return f"ACLCaption {self.text}"


class ACLObjects:
    def __init__(self):
        self.network = {}
        self.service = {}
        self.port = {}
        self.protocol = {}
        self.time = {}
        self.icmp = {}


class ACLRules:
    def __init__(self):
        self.rules = []

    def add(self, i):
        self.rules.append(i)

    def filter(self, target):
        r = set()
        for acl in self.rules:
            for i in target:
                if i & acl:
                    r.add(acl)
                    break
        return r


class ACLVersion:
    def __init__(self, v):
        self.version = v


import tatsu.ast

# from acltk.fwsmObjects import Names


class ACLParserOptions:
    def __init__(self, trace=False):
        assert isinstance(trace, bool), "unexpected type {} or class {}".format(
            type(trace), trace.__class__.__qualname__
        )
        self.trace = trace


class ACLConfig:
    def __init__(self, ast):
        self.timestamp = datetime.datetime.now()
        self.hostname = ""
        self.domainname = ""
        self.names = Names()
        self.interfaces = {}
        self.objects = ACLObjects()
        self.groups = ACLObjects()
        self.rules = ACLRules()
        self.access_groups = {}
        self.nat = {1: list(), 2: list(), 3: list()}
        for i in list(ast):
            if isinstance(i, tatsu.ast.AST) and "hostname" in i:
                self.hostname = i.hostname
            elif isinstance(i, tatsu.ast.AST) and "domain_name" in i:
                self.domainname = i.domain_name
            elif isinstance(i, ACLRule):
                self.rules.add(i)
            elif isinstance(i, Name):
                self.names.add(i)
            elif isinstance(i, Interface):
                self.interfaces[i.alias] = i
                for k, v in i.access_groups.items():
                    self.access_groups[v.name] = v
            elif isinstance(i, TimeRange):
                self.objects.time[i.name] = i
            elif isinstance(i, NetworkObject):
                # NAT auto via object network
                if hasattr(i, "nat"):
                    self.nat[2].append(i.nat)
                    delattr(i, "nat")
                if i.name not in self.objects.network:
                    self.objects.network[i.name] = i
            elif isinstance(i, ServiceObject):
                self.objects.service[i.name] = i
            elif isinstance(i, PortGroup):
                self.groups.port[i.name] = i
            elif isinstance(i, ServiceGroup):
                self.groups.service[i.name] = i
            elif isinstance(i, ProtocolGroup):
                self.groups.protocol[i.name] = i
            elif isinstance(i, ICMPGroup):
                self.groups.icmp[i.name] = i
            elif isinstance(i, NetworkGroup):
                self.groups.network[i.name] = i
            elif isinstance(i, ACLVersion):
                self.version = i.version
            elif isinstance(i, InterfaceAccessGroup):
                for j in self.interfaces.values():
                    if j.nameif == i.iface:
                        i.iface = j
                        j.access_groups[i.direction] = i
                        break
            elif isinstance(i, NATObject):
                position = 3 if ("after-auto", "after-object") & i.options.keys() else 1
                self.nat[position].append(i)
            else:
                continue
            ast.remove(i)

    @property
    def name(self):
        return f"{self.hostname}.{self.domainname}"

    @classmethod
    def _parse(cls, data, filename, options):
        assert isinstance(options, (None.__class__, ACLParserOptions)), "unexpected type {} or class {}".format(
            type(options), options.__class__.__qualname__
        )
        from acltk.fwsmObjects import fwsmConfig
        from acltk.iosObjects import iosConfig
        from acltk.pfsenseObjects import pfsenseConfig

        for i in [fwsmConfig, iosConfig, pfsenseConfig]:
            try:
                return i._parse(data, filename, options)
            except Exception as e:
                log.exception(e)
        raise ValueError("Invalid Config?")

    @classmethod
    def fromString(cls, _data, filename=None, options=None):
        assert isinstance(_data, str), "unexpected type {} or class {}".format(
            type(_data), _data.__class__.__qualname__
        )
        data = _data + "\n"
        return cls._parse(data, filename, options)

    @classmethod
    def fromFile(cls, f, options=None):
        data = f.read()
        data = data.decode("utf-8-sig")
        return cls.fromString(data, getattr(f, "name", "stdin"), options)

    @classmethod
    def fromPath(cls, path, options=None):
        with open(path, "rb") as f:
            return cls.fromFile(f, options)
        return None

    def resolve(self, r):
        for i in list(r):
            if isinstance(i, ACLRule):
                r.add(i.protocol)
                r.add(i.src.host)
                try:
                    r.add(i.src.port)
                    r.add(i.dst.port)
                except Exception as e:
                    print(e)
                r.add(i.dst.host)
                r.add(i.id)
                if i.protocol.name in ("icmp", "icmp6"):
                    if i.icmp:
                        r.add(i.icmp)
                for k, v in i.options.items():
                    if isinstance(v, TimeRange):
                        r.add(v)
                if i.id in self.access_groups:
                    r.add(self.access_groups[i.id])
            elif isinstance(i, NATObject):
                if i.real.src:
                    r.add(i.real.src.node)
                if i.real.dst:
                    r.add(i.real.dst.node)
                r.add(i.real.iface)
                r.add(i.real.service)

                if i.mapped.src:
                    r.add(i.mapped.src.node)
                if i.mapped.dst:
                    r.add(i.mapped.dst.node)
                r.add(i.mapped.iface)
                r.add(i.mapped.service)

        done = set()
        while True:
            for i in list(r):
                if i in done:
                    continue
                else:
                    done.add(i)
                if isinstance(i, (NetworkGroup, PortGroup, ServiceGroup, ProtocolGroup, ICMPGroup)):
                    r.add(i.__class__.__name__)
                    r = r.union(set(i.objects))
                    break
                elif isinstance(i, (Network, NetworkHost)):
                    if i.target:
                        r.add(i.target)
                        r.add("Names")
                    break
                elif isinstance(i, (NetworkObject, ServiceObject, TimeRange)):
                    r.add(i.__class__.__name__)
                    break
                elif isinstance(i, InterfaceAccessGroup):
                    r.add(i.iface)
                    r.add("Interface")
                    break
                elif isinstance(i, NATObject):
                    r.add("NAT")
            else:
                break

        return r

    def expand(self):
        todo = [
            (self.groups.network, NetworkGroup),
            (self.groups.port, PortGroup),
            (self.groups.service, ServiceGroup),
            (self.groups.protocol, ProtocolGroup),
            (self.groups.icmp, ICMPGroup),
        ]
        for l, n in todo:
            for group in l.values():
                group.expand()

    def filter(self, caf):
        from acltk.cafObjects import cafBlock

        assert isinstance(caf, cafBlock), f"unexpected type {type(caf)} or class {caf.__class__.__qualname__}"
        r = set()

        r.update(caf.run(self.rules, verbose=False))

        # FIXME abuse
        nat = ACLRules()
        nat.rules = list(itertools.chain.from_iterable(self.nat.values()))
        r.update(caf.run(nat, verbose=True))
        return r
