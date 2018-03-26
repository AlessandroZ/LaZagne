# -*- coding: utf-8 -*- 
#!/usr/bin/python

from lazagne.config.write_output import print_debug
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import *

class System(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'system', 'system')

	def run(self, software_name=None):
		pwdFound = []
		pwdFound += constant.keychains_pwd
		pwdFound += constant.system_pwd
		
		return pwdFound

