#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.header import Header
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
from lazagne.config import homes
import os

class Squirrel(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'squirrel', 'databases')

	def get_paths(self):
		return homes.get(file=os.path.join('.squirrel-sql', 'SQLAliases23.xml'))

	def parse_xml(self, path):
		pwdFound = []
		if os.path.exists(path):
			tree = ET.ElementTree(file=path)
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

	def run(self, software_name=None):
		all_passwords = []
		for path in self.get_paths():
			all_passwords += self.parse_xml(path)

		return all_passwords
