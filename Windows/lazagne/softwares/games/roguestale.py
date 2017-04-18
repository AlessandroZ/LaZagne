from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import os
import re

class RoguesTale(ModuleInfo):
	def __init__(self):
		options = {'command': '-r', 'action': 'store_true', 'dest': 'roguestale', 'help': 'Extract Rogue\'s Tale SHA1 password hashes.'}
		ModuleInfo.__init__(self, 'roguestale', 'games', options, need_to_be_in_env=False)
		
	def run(self, software_name = None):
		creds = []
		directory = constant.profile['USERPROFILE'] + '\\Documents\\Rogue\'s Tale\\users'
		
		# The actual user details are stored in *.userdata files
		if not os.path.exists(directory):
			print_debug('INFO', 'Rogue\'s Tale appears to not be installed.')
			return
		
		files = os.listdir(directory)
		
		for file in files:
			if re.match('.*\.userdata',file):
				# We've found a user file, now extract the hash and username				
				
				xmlfile = directory + '\\' + file
				tree = ET.ElementTree(file=xmlfile)
				root = tree.getroot()
				
				# Double check to make sure that the file is valid
				if root.tag != 'user':
					print_debug('Profile %s does not appear to be valid' % file)
					continue
				
				# Now save it to credentials
				creds.append(
					{
						'Login'	: root.attrib['username'], 
						'Hash'	: root.attrib['password']
					}
				)
		
		return creds
