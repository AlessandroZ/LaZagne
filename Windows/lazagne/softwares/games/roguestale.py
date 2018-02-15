# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import os
import re

class RoguesTale(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'roguestale', 'games')
		
	def run(self, software_name=None):
		creds 		= []
		directory 	= constant.profile['USERPROFILE'] + u'\\Documents\\Rogue\'s Tale\\users'
		
		# The actual user details are stored in *.userdata files
		if os.path.exists(directory):
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
