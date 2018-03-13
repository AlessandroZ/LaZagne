# -*- coding: utf-8 -*- 
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.winstructure import *

class Credman(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'credman', 'windows', dpapi_used=True)
	
	# FOR XP
	# 	entropy = 'abe2869f-9b47-4cd9-a358-c22904dba7f7\0' # FOR CRED_TYPE_GENERIC
	# 	entropy = '82BD0E67-9FEA-4748-8672-D5EFE5B779B0\0' # FOR CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
	
	def run(self, software_name=None):
		pwdFound	= []
		creds 		= POINTER(PCREDENTIAL)()
		count 		= c_ulong()

		if CredEnumerate(None, 0, byref(count), byref(creds)) == 1:
			for i in range(count.value):
				c = creds[i].contents
				if c.Type == CRED_TYPE_GENERIC or c.Type == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
					# For XP:
					# - password are encrypted with specific salt depending on its Type
					# - call CryptUnprotectData(byref(blobIn), None, byref(blobEntropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(blobOut))
					
					# Remove password too long
					if c.CredentialBlobSize.real < 200:
						pwdFound.append(
							{
								'URL'		:	c.TargetName, 
								'Login'		: 	c.UserName, 
								'Password'	:	c.CredentialBlob[:c.CredentialBlobSize.real].replace('\x00', '')
							}
						)
			CredFree(creds)
		return pwdFound
