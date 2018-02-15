# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import os

class Squirrel(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, name='squirrel', category='databases')

	def run(self, software_name=None):
		path = os.path.join(constant.profile['USERPROFILE'], u'.squirrel-sql', u'SQLAliases23.xml')
		if os.path.exists(path):
			tree = ET.ElementTree(file=path)
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

		