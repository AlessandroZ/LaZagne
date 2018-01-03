from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import base64
import os

class Cyberduck(ModuleInfo):
	def __init__(self):
		options = {'command': '-c', 'action': 'store_true', 'dest': 'cyberduck', 'help': 'cyberduck'}
		ModuleInfo.__init__(self, 'cyberduck', 'sysadmin', options)

	# find the user.config file containing passwords
	def get_application_path(self):
		directory = os.path.join(constant.profile['APPDATA'], u'\Cyberduck')
		if os.path.exists(directory):
			for dr in os.listdir(directory):
				if dr.startswith(u'Cyberduck'):
					for d in os.listdir(os.path.join(directory, unicode(dr))):
						path = os.path.join(directory, unicode(dr), unicode(d), u'user.config')
						if os.path.exists(path):
							return path
			
			return 'User_profil_not_found'
		else:
			return False
			
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
					password = Win32CryptUnprotectData(encrypted_password)
					values['Password'] = password
					
					pwdFound.append(values)
			except Exception as e:
				print_debug('DEBUG', '{0}'.format(e))

		return pwdFound
		
	# main function
	def run(self, software_name = None):
		path = self.get_application_path()
		if not path:
			print_debug('INFO', 'Cyberduck not installed.')
		elif path == 'User_profil_not_found':
			print_debug('INFO', 'User profil has not been found.')
		else:
			return self.parse_xml(path)
			