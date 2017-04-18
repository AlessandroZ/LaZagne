from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import os

class Pidgin(ModuleInfo):
	def __init__(self):
		options = {'command': '-p', 'action': 'store_true', 'dest': 'pidgin', 'help': 'pidgin'}
		ModuleInfo.__init__(self, 'pidgin', 'chats', options, need_to_be_in_env=False)

	def run(self, software_name = None):		
		path = os.path.join(constant.profile['APPDATA'], '.purple', 'accounts.xml')
		
		if os.path.exists(path):
			tree = ET.ElementTree(file=path)
			
			root = tree.getroot()
			accounts = root.getchildren()
			
			pwdFound = []
			for a in accounts:
				values = {}
				aa = a.getchildren()
				noPass = True

				for tag in aa:
					cpt = 0
					if tag.tag == 'name':
						cpt = 1
						values['Login'] = tag.text
					
					if tag.tag == 'password':
						values['Password'] = tag.text
						noPass = False
					
				if noPass == False:
					pwdFound.append(values)

			return pwdFound
		else:
			print_debug('INFO', 'Pidgin not installed.')
			
