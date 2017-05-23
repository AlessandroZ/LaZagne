import xml.etree.cElementTree as ET
from lazagne.config.header import Header
from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config import homes

import os

class Squirrel(ModuleInfo):
	def __init__(self):
		options = {'command': '-q', 'action': 'store_true', 'dest': 'squirrel', 'help': 'squirrel'}
		ModuleInfo.__init__(self, 'squirrel', 'database', options)

	def get_paths(self):
		return homes.get(file=os.path.join('.squirrel-sql', 'SQLAliases23.xml'))

	def parse_xml(self, xml_file):
		tree = ET.ElementTree(file=xml_file)
		pwdFound = []
		for elem in tree.iter('Bean'):
			values = {}
			for e in elem:
				if e.tag == 'name':
					values['Name'] = e.text

				elif e.tag == 'url':
					values['URL'] = e.text

				elif e.tag == 'userName':
					values['Login'] = e.text

				elif e.tag == 'password':
					values['Password'] = e.text

			if len(values):
				pwdFound.append(values)

		return pwdFound

	# Main function
	def run(self, software_name = None):
		all_passwords = []

		for path in self.get_paths():
			all_passwords += self.parse_xml(path)

		return all_passwords
