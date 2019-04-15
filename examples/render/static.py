import datetime
from jinja2 import FileSystemLoader, Environment
from acltk import ACLConfig, cafBlock
from acltk.aclObjects import NetworkGroup, PortGroup, ServiceGroup, ProtocolGroup, TimeRange, Network, NetworkHost, \
	NetworkObject, ServiceObject


def main():
	import argparse
	parser = argparse.ArgumentParser(description="jinja2 rendering example")
	parser.add_argument('--caf', help="the caf filter", default=None)
	parser.add_argument('--show-not-selected', action="store_true", default=False)
	parser.add_argument('--expand', action="store_true", default=False)
	parser.add_argument('--output', '-o', help="the output file", default='render.html')
	parser.add_argument('--sort', help="sort group members", default=False, action='store_true')
	parser.add_argument('acls', help="the ACLs")

	args = parser.parse_args()

	loader = FileSystemLoader('./tpl/')
	env = Environment(loader=loader, extensions=['jinja2.ext.loopcontrols'])
	for i in env.list_templates():
		print(i)
	aclconfig = ACLConfig.parse(args.acls)

	if args.expand:
		aclconfig.expand()

	template = env.get_template('static.html')

	selection = None
	caffilter = ""
	if args.caf:
		caf = cafBlock.parse(args.caf)
		r = caf.run(aclconfig.rules, verbose=True)
		caffilter = open(args.caf).read()
		selection = aclconfig.resolve(r)

	if args.sort:
		for i in ['network','service','port','protocol']:
			grps = getattr(aclconfig.groups, i)
			for grp in grps.values():
				grp.sort()

	args.time = datetime.datetime.now()

	with open(args.output,'wt') as f:
		f.write(template.render(aclconfig=aclconfig, selection=selection, caf=caffilter, args=args))

if __name__ == '__main__':
	main()
