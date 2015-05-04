import xml.etree.cElementTree as ET
import os
from config.write_output import print_output, print_debug
from config.constant import *
from config.header import Header
from config.moduleInfo import ModuleInfo

class Squirrel(ModuleInfo):
	def __init__(self):
		options = {'command': '-q', 'action': 'store_true', 'dest': 'squirrel', 'help': 'squirrel'}
		ModuleInfo.__init__(self, 'squirrel', 'database', options)

	def get_path(self):
		if 'HOMEPATH' in os.environ:
			path = os.environ['HOMEPATH'] + os.sep + '.squirrel-sql'
			if os.path.exists(path):
				return path
			else:
				return 'Not_Found'
		else:
			return 'var_Env_Not_Found'
	
	def parse_xml(self, xml_file):
		tree = ET.ElementTree(file=xml_file)
		pwdFound = []
		for elem in tree.iter('Bean'):
			values = {}
			for e in elem:
				if e.tag == 'name':
					values['name'] = e.text
				
				elif e.tag == 'url':
					values['url'] = e.text
				
				elif e.tag == 'userName':
					values['userName'] = e.text
				
				elif e.tag == 'password':
					values['password'] = e.text
			
			if len(values):
				pwdFound.append(values)
			
		# print the results
		print_output("Squirrel", pwdFound)
		
	# Main function
	def run(self):
		# print title
		Header().title_debug('Squirrel')
		
		path = self.get_path()
		if path == 'Not_Found':
			print_debug('INFO', 'Squirrel not installed')
		elif path == 'var_Env_Not_Found':
			print_debug('ERROR', 'The HOMEPATH environment variable is not defined.')
		else:
			path += os.sep + 'SQLAliases23.xml'
			if os.path.exists(path):
				self.parse_xml(path)
			else:
				print_debug('WARNING', 'xml fil SQLAliases23.xml containing passwords has not be found')
		