import glob
import unittest
import grako.exceptions
from acltk import ACLConfig

from acltk.pfsenseObjects import pfsenseConfig


class cafTestFilter(unittest.TestCase):
	def test_0(self):
		self.acls = pfsenseConfig.fromPath('acl/pfsense.xml')

	def test_1(self):
		pass

