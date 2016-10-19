#!/usr/bin/env python
import os
from lazagne.config.write_output import  print_debug
from lazagne.config.moduleInfo import ModuleInfo

class Env_variable(ModuleInfo):
	def __init__(self):
		options = {'command': '-e', 'action': 'store_true', 'dest': 'env', 'help': 'environment variables'}
		ModuleInfo.__init__(self, 'Environment variables', 'sysadmin', options)

	def run(self, software_name = None):
		values = {}
		pwdFound = []
		
		# --------- http_proxy --------
		tmp = ''
		if 'http_proxy' in os.environ:
			tmp = 'http_proxy'
		elif 'HTTP_Proxy' in os.environ:
			tmp = 'HTTP_Proxy'
		
		if tmp:
			values["Login"] = tmp
			values["Password"] = os.environ[tmp]
			pwdFound.append(values)
			
		# --------- https_proxy --------
		tmp = ''
		if 'https_proxy' in os.environ:
			tmp = 'https_proxy'
		elif 'HTTPS_Proxy' in os.environ:
			tmp = 'HTTPS_Proxy'
		
		if tmp:
			values["Login"] = tmp
			values["Password"] = os.environ[tmp]
			pwdFound.append(values)
		
		tab = ['passwd', 'pwd', 'pass', 'password']
		for i in os.environ:
			for t in tab:
				if (t.upper() in i.upper()) and (i.upper() != 'PWD') and (i.upper() != 'OLDPWD'):
					values["Login"] = i
					values["Password"] = os.environ[i]
		pwdFound.append(values)
		
		# write credentials into a text file
		if len(values) != 0:
			return pwdFound
		
		else:
			print_debug('INFO', 'No passwords stored in the environment variables.')
		