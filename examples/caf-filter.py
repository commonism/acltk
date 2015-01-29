#!/usr/bin/python3

from acltk.aclObjects import ACLConfig

from acltk.cafObjects import cafBlock


def main(args):
	ast = cafBlock.fromPath(args.file, trace=args.trace)
	print(ast)
	aclConfig = ACLConfig.fromPath(args.acls)
	r = ast.run(aclConfig.rules)
	print(len(r))
	for i in r:
		print(i)


def run_main():
	import argparse

	parser = argparse.ArgumentParser(description="caf filtering example")
	parser.add_argument('-t', '--trace', action='store_true', help="output trace information")
	parser.add_argument('file', metavar="FILE", help="the input file to parse")
	parser.add_argument('acls', help="the ACL input file to parse")
	args = parser.parse_args()

	main(args)


if __name__ == '__main__':
	run_main()
