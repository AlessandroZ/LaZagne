from lazagne.config.write_output import print_debug
from lazagne.config.constant import *
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
# import struct

class Credman(ModuleInfo):
	def __init__(self):
		options = {'command': '-n', 'action': 'store_true', 'dest': 'credential manager', 'help': 'credential manager'}
		ModuleInfo.__init__(self, 'Generic Network and Dot Net', 'windows', options, cannot_be_impersonate_using_tokens=True)
	
	# FOR XP
	# def getData(self, blobOut):
	# 	cbData = int(blobOut.cbData)
	# 	pbData = blobOut.pbData
	# 	buffer = c_buffer(cbData)
	# 	memcpy(buffer, pbData, cbData)
	# 	LocalFree(pbData);
	# 	return buffer.raw

	# def get_entropy(self):
	# 	entropy = 'abe2869f-9b47-4cd9-a358-c22904dba7f7\0' # FOR CRED_TYPE_GENERIC
	# 	entropy = '82BD0E67-9FEA-4748-8672-D5EFE5B779B0\0' # FOR CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
		
	# 	s = ''
	# 	for c in entropy:
	# 		s += struct.pack('<h', ord(c) << 2)
	# 		entropy = s
	# 	return s

	# def Win32CryptUnprotectData(self, cipherText, entropy):
	# 	bufferIn = c_buffer(cipherText, len(cipherText))
	# 	blobIn = DATA_BLOB(len(cipherText), bufferIn)
	# 	bufferEntropy = c_buffer(entropy, len(entropy))
	# 	blobEntropy = DATA_BLOB(len(entropy), bufferEntropy)
	# 	blobOut = DATA_BLOB()

	# 	if CryptUnprotectData(byref(blobIn), None, byref(blobEntropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(blobOut)):
	# 		return self.getData(blobOut)
	# 	else:
	# 		return 'failed'
	
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



