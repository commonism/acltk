import collections
import datetime
import urllib
import urllib.error
import urllib.request
import ipaddress
from acltk.aclSemantics import aclSemantics, aclParser
from acltk.aclObjects import Interface, ACLConfig, ACLRuleOptionInterface, ACLRuleOptionLog, ACLRuleOptionInActive, NetworkAny, NetworkInterface, ACLRule, ACLCaption, ACLNode, Protocol, Network, NetworkHost, NetworkGroup, PortGroup, Port, PortRange, ICMP
from acltk.pfsenseObjects import pfsenseConfig
import tatsu.ast
import xml.etree.ElementTree as ET
import logging

log = logging.getLogger('acltk.pfsense')

class pfsenseParserOptions:
	def __init__(self, fetch_urltable=True):
		self.fetch_urltable = fetch_urltable

class pfsenseParser(aclParser):
	def __init__(self, options = None):
		aclParser.__init__(self)
		self._options = options or pfsenseParserOptions()
		self.interface_map = dict()  # optX -> alias

	def parse(self, data, filename='config.xml', trace=False):
		root = ET.fromstring(data)
		ast = []
		if not root.tag in ('pfsense','opnsense'):
			raise ValueError(root.tag)
		for tag in ['revision','aliases','interfaces','filter','system', 'filter/separator']:

			for e in root.findall(tag):
				name = '_parse_{}'.format(tag.replace('/','_'))
				call = getattr(self, name, None)
				if not call:
					continue
				obj = call(e)
				ast.extend(obj)
		return pfsenseConfig(ast)

	def _parse_revision(self, root):
		birth = None
		for i in list(root):
			if i.tag == 'time':
				birth = datetime.datetime.fromtimestamp(int(i.text))
				break
		else:
			birth = datetime.datetime.now()
		return tatsu.ast.AST(**{'birth': birth})

	def _parse_system(self, root):
		ast = []
		domain = hostname = None
		for i in list(root):
			if i.tag == 'domain':
				domain = i.text
			elif i.tag == 'hostname':
				hostname = i.text
		ast.append(tatsu.ast.AST(**{'hostname': '{hostname}.{domain}'.format(**locals())}))
		return ast

	def _parse_interfaces(self, root):
		ast = []
		for i in list(root):
			values = {'alias':i.tag}
			for d in list(i):
				values[d.tag] = d.text
			values['name'] = i.tag
			if 'ipaddr' in values:
				if values['ipaddr'] != 'dhcp':
					details = [tatsu.ast.AST(**{'type':['ip','address'],'value':[values['ipaddr'],values['subnet']]})]
				else:
					details = [tatsu.ast.AST(**{'type': 'nameif', 'value': values['if']})]
			else:
				details = [tatsu.ast.AST(**{'type': 'nameif', 'value': values['if']})]

			alias = i.tag
			if alias.startswith('opt'):
				details.append(tatsu.ast.AST(**{'type': 'description', 'value': alias}))
				alias = values.get('descr', alias)
			else:
				details.append(tatsu.ast.AST(**{'type': 'description', 'value': values.get('descr', '')}))

			obj = Interface(alias=alias, details=details)
			ast.append(obj)

			self.interfaces[obj.alias] = obj
			self.interface_map[obj.description] = obj.alias

		return ast

	def _parse_aliases(self, root):
#		print(ET.tostring(root))
		ast = []
		for i in list(root):
			values = {}
			for v in list(i):
				values[v.tag] = v.text
			g = None
			if values['type'] == 'host':
				g = NetworkGroup(values['name'], values['descr'])
				if values['address']:
					for addr in values['address'].split(" "):
						g.add(NetworkHost(addr))
				self.network_groups[values['name']] = g
			elif values['type'] == 'network':
				g = NetworkGroup(values['name'], values['descr'])
				if values['address']:
					for addr in values['address'].split(" "):
						g.add(Network(*addr.split('/')))
				self.network_groups[values['name']] = g
			elif values['type'] == 'urltable':
				g = NetworkGroup(values['name'], values['descr'])
				self.network_groups[values['name']] = g

				if self._options.fetch_urltable:
					try:
						req = urllib.request.urlopen(values['url'])
						data = req.read().decode('utf-8')
						for line in data.split('\n'):
							line = line.strip()
							if not '/' in line:
								try:
									addr = ipaddress.ip_address(line)
									g.add(NetworkHost(line))
									continue
								except:
									pass
							else:
								try:
									addr = ipaddress.ip_network(line)
									g.add(Network(*line.split('/')))
									continue
								except:
									pass
					except urllib.error.HTTPError as e0:
						pass
					except Exception as e1:
						log.exception(e1)
				else:
					g.add(NetworkAny())


			elif values['type'] == 'port':
				g = PortGroup(values['name'], Protocol('any'), values['descr'])
				if values['address']:
					for addr in values['address'].split(" "):
						if ':' in addr:
							g.add(PortRange(*addr.split(':')))
						else:
							g.add(Port('eq', addr))
				self.port_groups[values['name']] = g
			else:
				raise ValueError(values['type'])
			ast.append(g)
		return ast


	def _parse_filter(self, root):
		ast = []
		now = datetime.datetime.now()
		for i in list(root):
			if i.tag == 'rule':
				rule = self._parse_filter__rule(i, now)
				ast.append(rule)
			elif i.tag == 'separator':
				separators = collections.defaultdict(lambda: collections.defaultdict(lambda: list()))
				for ifname in list(i):
					for sep in list(ifname):
						# EXML - pfsense does not use attribute to denote the index of the separator but "sep{idx}" as tag instead
						idx = int(sep.tag[3:])
						values = {x.tag: x.text for x in list(sep)}
						iface = values['if']
						if iface == 'floatingrules':
							iface = 'floating'
						else:
							iface = self.interface_map.get(iface, iface)
						# EXML - pfsense uses "fr{idx}" to denote the rows number
						row = int(values['row'][2:])
						separators[iface][row].append(ACLCaption(bg=values['color'], text=values['text']))


				ifname = None
				last = 0
				sidx = 0
				for idx,rule in enumerate(ast):
					if rule.id != ifname:
						last = idx
						ifname = rule.id
					sidx = idx - last

					if ifname in separators:
						if sidx in separators[ifname]:
							ast[idx].head = separators[ifname][sidx]
			else:
				raise ValueError(i.tag)
		return ast

	def _parse_filter__rule(self, i, now):
		icmp = None
		# EXML - pfsense ignorance of attributes & cardinality is a headache
		values = {'protocol': 'any', 'source': ACLNode(NetworkAny()), 'destination': ACLNode(NetworkAny()),
				  'created': now, 'updated': now, 'log': False, 'statetype':'keep state', 'floating':'no'}
		valueable = ['tracker', 'type', 'interface', 'floating', 'direction', 'quick', 'protocol', 'descr', 'disabled','statetype']
		for v in list(i):
			if v.tag in valueable:
				values[v.tag] = v.text
			elif v.tag == 'log':
				values['log'] = True
			elif v.tag in ['source', 'destination']:
				#					print(v.tag)
				address = port = None
				for n in list(v):
					if n.tag == 'any':
						address = NetworkAny()
					elif n.tag == 'address':
						address = n.text
						try:
							address = self.network_groups[address]
						except KeyError as e:
							if '/' in address:
								address = Network(*address.split('/'))
							else:
								address = NetworkHost(address)
					elif n.tag == 'port':
						port = n.text
						try:
							port = self.port_groups[port]
						except KeyError as e:
							if '-' in port:
								port = PortRange(*port.split('-', 2))
							else:
								port = Port('eq', port)
					elif n.tag == 'network':
						address = n.text
						if address in self.interfaces:
							address = NetworkInterface(self.interfaces[address].alias)
						else:
							raise ValueError(n.text)
					else:
						raise ValueError(n.tag)
				values[v.tag] = ACLNode(address, port)
			elif v.tag in ['created', 'updated']:
				for n in list(v):
					if n.tag == 'time':
						values[v.tag] = datetime.datetime.fromtimestamp(int(n.text))
			elif v.tag == 'icmptype':
				icmp = ICMP(v.text, None)
			elif v.tag in frozenset(
					['id', 'ipprotocol', 'tag', 'tagged', 'max', 'max-src-nodes', 'max-src-conn', 'max-src-states',
					 'statetimeout', 'os']):
				continue
			else:
				raise ValueError("unknown data {}".format(v.tag))

		options = {'xref': values.get('tracker', -1)}

		if values['floating'] == 'yes':
			iface = 'floating'
			ifname = [self.interface_map.get(i,i) for i in values['interface'].split(',')]
			options['floating'] = ACLRuleOptionInterface(ifname, values['direction'])
		else:
			iface = values['interface']

			# lookup interface alias, default to old name
			iface = self.interface_map.get(iface, iface)
		if 'disabled' in values:
			options['inactive'] = ACLRuleOptionInActive()

		if values['log']:
			options['log'] = ACLRuleOptionLog([])

		if values['statetype'] != 'keep state':
			options['statetype'] = values['statetype']

		dates = "c: {} ({} days) / m: {} ({} days)".format(values['created'].strftime("%Y-%m-%d"),
														   (now - values['created']).days,
														   values['updated'].strftime("%Y-%m-%d"),
														   (now - values['updated']).days)

		return ACLRule(id=iface,
						   mode={'pass': 'permit'}.get(values['type'], 'deny'),
						   protocol=Protocol(values['protocol']),
						   src=values['source'],
						   dst=values['destination'],
						   remark=[values['descr'], dates],
						   options=options,
						   icmp=icmp)
