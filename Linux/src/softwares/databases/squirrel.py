import xml.etree.cElementTree as ET
from config.header import Header
from config.constant import *
from config.write_output import print_debug, print_output
from config.moduleInfo import ModuleInfo
import os

class Squirrel(ModuleInfo):
	def __init__(self):
		options = {'command': '-q', 'action': 'store_true', 'dest': 'squirrel', 'help': 'squirrel'}
		ModuleInfo.__init__(self, 'squirrel', 'database', options)

	def get_path(self):
		
		path = '~/.squirrel-sql'
		path = os.path.expanduser(path)
		
		if os.path.exists(path):
			return path
		else:
			return 'Not_Found'
	
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
					values['UserName'] = e.text
				
				elif e.tag == 'password':
					values['Password'] = e.text
			
			if len(values):
				pwdFound.append(values)
		
		# print the results
		print_output('Squirrel', pwdFound)
		
	# Main function
	def run(self):
		# print the title
		Header().title_info('Squirrel')
		
		path = self.get_path()
		if path == 'Not_Found':
			print_debug('INFO', 'Squirrel not installed')
		
		else:
			path += os.sep + 'SQLAliases23.xml'
			if os.path.exists(path):
				self.parse_xml(path)
			else:
				print_debug('WARNING', 'xml file containing passwords has not be found')
		