from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *

class Credman(ModuleInfo):
	def __init__(self):
		options = {'command': '--cred', 'action': 'store_true', 'dest': 'credential manager', 'help': 'credential manager'}
		ModuleInfo.__init__(self, 'Generic Network and Dot Net', 'windows', options, cannot_be_impersonate_using_tokens=False)
	
	# FOR XP
	# 	entropy = 'abe2869f-9b47-4cd9-a358-c22904dba7f7\0' # FOR CRED_TYPE_GENERIC
	# 	entropy = '82BD0E67-9FEA-4748-8672-D5EFE5B779B0\0' # FOR CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
	
	def run(self, software_name = None):		
		pwdFound = []
		creds = POINTER(PCREDENTIAL)()
		count = c_ulong()
		if CredEnumerate(None, 0, byref(count), byref(creds)):
			for i in range(count.value):
				c = creds[i].contents
				if c.Type == CRED_TYPE_GENERIC or c.Type == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
					# For XP:
					# - password are encrypted with specific salt depending on its Type
					# - call CryptUnprotectData(byref(blobIn), None, byref(blobEntropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(blobOut))

					pwdFound.append(
						{
							'URL'		:	c.TargetName, 
							'Login'		: 	c.UserName, 
							'Password'	:	c.CredentialBlob[:c.CredentialBlobSize.real:2]
						}
					)
			CredFree(creds)
		return pwdFound



