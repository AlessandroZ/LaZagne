import xml.etree.cElementTree as ET
import os, re
from config.constant import *
from config.write_output import print_output, print_debug
from config.header import Header
from config.moduleInfo import ModuleInfo

class RoguesTale(ModuleInfo):
	def __init__(self):
		options = {'command': '-r', 'action': 'store_true', 'dest': 'roguestale', 'help': 'Extract Rogue\'s Tale SHA1 password hashes.'}
		ModuleInfo.__init__(self, 'roguestale', 'games', options)
		
	def run(self):
		# print title
		Header().title_info('Rogue\'s Tale')
		creds = []
		
		if 'USERPROFILE' in os.environ:
			directory = os.environ['USERPROFILE'] + '\\Documents\\Rogue\'s Tale\\users'
		else:
			print_debug('ERROR', 'The USERPROFILE environment variable is not defined.')
			return
		
		# The actual user details are stored in *.userdata files
		if not os.path.exists(directory):
			print_debug('INFO', 'Rogue\'s Tale appears to not be installed.')
			return
		
		files = os.listdir(directory)
		
		for file in files:
			if re.match('.*\.userdata',file):
				# We've found a user file, now extract the hash and username
				values = {}
				
				xmlfile = directory + '\\' + file
				tree=ET.ElementTree(file=xmlfile)
				root=tree.getroot()
				
				# Double check to make sure that the file is valid
				if root.tag != 'user':
					print_debug('Profile ' + file + ' does not appear to be valid')
					continue
				
				# Now save it to credentials
				values['Login'] = root.attrib['username']
				values['Hash'] = root.attrib['password']
				creds.append(values)
		
		print_output("Rogue's Tale", creds)
					
				
