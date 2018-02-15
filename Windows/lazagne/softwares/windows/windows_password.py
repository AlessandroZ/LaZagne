# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.dpapi_structure import *
from lazagne.config.constant import *

class WindowsPassword(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'windows', 'windows')

	def get_hash(self, context):
		constant.dpapi.get_DPAPI_hash(context=context)
		if constant.dpapi_hash:
			h = {
					'DPAPI_Hash_{context}'.format(context=context.capitalize()) : constant.dpapi_hash
				}
			constant.dpapi_hash = None
			return  h
		else:
			return False

	def run(self, software_name=None):
		pwdFound = []

		# check password founds as windows password
		if not constant.dpapi: 
			constant.dpapi = Decrypt_DPAPI(password=constant.user_password)
			if constant.dpapi.dpapi_ok:
				password = constant.user_password
			else:
				# add user login for weak password (login = password)
				constant.passwordFound.append(constant.username)
				password = constant.dpapi.check_credentials(constant.passwordFound)
				
			# check if the password has been found again 
			if constant.dpapi.dpapi_ok:
				constant.dpapi = Decrypt_DPAPI(password=password)
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

				print_debug('INFO', 'Windows passwords not found.\nTry to bruteforce this hash (using john or hashcat) depending on your context (domain environment or not)')
				for context in ['local', 'domain']:
					h = self.get_hash(context)
					if h:
						pwdFound.append(h)
				
				pass

		return pwdFound
