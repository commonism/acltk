from acltk.acl import aclParser
from acltk.aclObjects import NetworkAny, NetworkHost, ACLNode, ACLRule, Network, ACLConfig, ACLParserOptions


def main():
    import argparse

    parser = argparse.ArgumentParser(description="manual acl filtering example")
    parser.add_argument("-t", "--trace", action="store_true", help="output trace information")
    parser.add_argument("filename", metavar="FILE", help="the input file to parse")
    args = parser.parse_args()

    config = ACLConfig.fromPath(args.filename, options=ACLParserOptions(trace=args.trace))

    anyany = set()
    for acl in config.rules.rules:
        if isinstance(acl.src.host, NetworkAny) and isinstance(acl.dst.host, NetworkAny):
            anyany.add(acl)

    print(f"anyany {len(anyany)}")

    target = [
        ACLRule(id="inside_in", source=ACLNode(NetworkAny()), dest=ACLNode(Network(address="10.2.0.0", netmask="24"))),
        ACLRule(id="outside_in", dest=ACLNode(NetworkAny()), source=ACLNode(Network(address="10.2.0.0", netmask="24"))),
    ]
    base = config.rules.filter(target)
    print(f"base {len(base)}")

    u = set.union(anyany, base)
    print(f"union {len(u)}")

    target = [
        ACLRule(id="inside_in", source=ACLNode(NetworkAny()), dest=ACLNode(Network(address="10.1.0.0", netmask="24"))),
        ACLRule(id="outside_in", dest=ACLNode(NetworkAny()), source=ACLNode(Network(address="10.1.0.0", netmask="24"))),
    ]

    rules = config.rules.filter(target)
    print(f"rules {len(rules)}")

    remain = rules.difference(u)
    print(f"remain {len(remain)}")

    # for i in remain:
    # print(i)
    for i in config.rules.rules:
        if i in remain:
            print(i)


if __name__ == "__main__":
    main()
