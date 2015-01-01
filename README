                                       acltk

This library is meant to parse Cisco ACLs and apply filters on them.

 INSTALLATION
Install
 * python 3.4 (we need ipaddress)
 * grako 3.4 (what I used)

 OPERATION
from acltk import ACLConfig, cafBlock
config = ACLConfig.parse("acl.conf")
filter = cafBlock.parse("filter.caf")
r = cafBlock.run(config)

See examples/ for examples.
 acl-filter.py - shows how to create acl filters manually.
python3 examples/acl-filter.py tests/acl/all.conf

 caf-filter.py - shows how to use acls combined with caf filters
python3 examples/caf-filter.py tests/caf/nested.caf tests/acl/all.conf

 render/static.py - jinja enabled rendering of the acls

 render/dynamic.py - flask based webservice for rendering/filtering


 CAF
caf is the Cisco ACL Filter language, designed to filter Cisco ACLs.
Currently you can filter ACLs by
id name
ip src|dst {addr ["/" netmask]}+
ip src|dst ANY ANY4 ANY6 any any4 any6

ip ... "ANY*" is special, it will filter out "any" rules.
e.g.
(
    ip src ANY
    ip dst ANY
)
will match any any rule such as
access-list inside_in permit tcp any any port 53

There are set operations defined on these sets, valid operations are:
 union
 intersect
 except

You can use braces to preference operations properly

( id A except ip src ANY ) union ( id B except ip src ANY )

C++ style multi line comments can be used to document caf filters.

/* we want all rules matching 10.1.0.0/24 on ids outside_in and inside_in
   without the rules matching any any
   without the rules which apply for 10.2.0.0/24
*/
(
    /* rules for 10.1.0.0/24 */
    (
        id outside_in
        ip dst 10.1.0.0/24
    )
    union
    (
        id inside_in
        ip src 10.1.0.0/24
    )
)
except
(
    (   /* any any */
        ip src ANY
        ip dst ANY
    )
)
except
(
    ip dst 10.2.0.0/24
    union
    ip src 10.2.0.0/24
)

