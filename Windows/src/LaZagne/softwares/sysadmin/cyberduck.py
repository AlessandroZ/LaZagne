import sqlite3
import win32crypt
import sys, os, platform, base64
import xml.etree.cElementTree as ET
from config.write_output import print_output, print_debug
from config.constant import *
from config.header import Header
from config.moduleInfo import ModuleInfo

class Cyberduck(ModuleInfo):
	def __init__(self):
		options = {'command': '-c', 'action': 'store_true', 'dest': 'cyberduck', 'help': 'cyberduck'}
		ModuleInfo.__init__(self, 'cyberduck', 'sysadmin', options)

	# find the user.config file containing passwords
	def get_path(self):
		if 'APPDATA' in os.environ:
			directory = os.environ['APPDATA'] + '\Cyberduck'
			
			if os.path.exists(directory):
				for dir in os.listdir(directory):
					if dir.startswith('Cyberduck'):
						for d in os.listdir(directory + os.sep + dir):
							path = directory + os.sep + dir + os.sep + d + os.sep + 'user.config'
							if os.path.exists(path):
								return path
				
				return 'User_profil_not_found'
			else:
				return 'CYBERDUCK_NOT_EXISTS'
		else:
			return 'APPDATA_NOT_FOUND'
			
	# parse the xml file
	def parse_xml(self, xml_file):
		tree = ET.ElementTree(file=xml_file)
		
		pwdFound = []
		for elem in tree.iter():
			values = {}
			try:
				if elem.attrib['name'].startswith('ftp') or elem.attrib['name'].startswith('ftps') or elem.attrib['name'].startswith('sftp') or elem.attrib['name'].startswith('http') or elem.attrib['name'].startswith('https'):
					values['URL'] = elem.attrib['name']
					encrypted_password = base64.b64decode(elem.attrib['value'])
					password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
					values['Password'] = password
					
					pwdFound.append(values)
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))

		# print the results
		print_output("Cyberduck", pwdFound)
		
	# main function
	def run(self):
		# print title
		Header().title_info('Cyberduck')
		
		path = self.get_path()
		if path == 'CYBERDUCK_NOT_EXISTS':
			print_debug('INFO', 'Cyberduck not installed.')
		elif path == 'User_profil_not_found':
			print_debug('INFO', 'User profil has not been found.')
		elif path == 'APPDATA_NOT_FOUND': 
			print_debug('ERROR', 'The APPDATA environment variable is not defined.')
		else:
			self.parse_xml(path)
			