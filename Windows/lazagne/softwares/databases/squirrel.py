from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import os

class Squirrel(ModuleInfo):
	def __init__(self):
		options = {'command': '-q', 'action': 'store_true', 'dest': 'squirrel', 'help': 'squirrel'}
		ModuleInfo.__init__(self, 'squirrel', 'database', options)

	def get_application_path(self):
		path = os.path.join(constant.profile['USERPROFILE'], '.squirrel-sql')
		if os.path.exists(path):
			return path
		else:
			return False
	
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
			
			if values:
				pwdFound.append(values)
			
		return pwdFound
		
	# Main function
	def run(self, software_name = None):
		path = self.get_application_path()
		if not path:
			print_debug('INFO', 'Squirrel not installed')
		else:
			path = os.path.join(path, 'SQLAliases23.xml')
			if os.path.exists(path):
				return self.parse_xml(path)
			else:
				print_debug('WARNING', 'xml fil SQLAliases23.xml containing passwords has not be found')
		