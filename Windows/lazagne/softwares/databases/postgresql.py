# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import *
import os

class PostgreSQL(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, name='postgresql', category='databases')

	def run(self, software_name=None):
		path = os.path.join(constant.profile['APPDATA'], u'postgresql', u'pgpass.conf')
		if os.path.exists(path):
			with open(path) as f:
				data = f.readlines()

				pwdFound = []
				for line in data:
					try:
						items = line.strip().split(':')

						values = {}
						values['Hostname'] = items[0]
						values['Port'] = items[1]
						values['DB'] = items[2]
						values['Username'] = items[3]
						values['Password'] = items[4]

						pwdFound.append(values)

					except:
						pass
				
				return pwdFound
