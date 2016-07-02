import struct, platform, win32cred
from ctypes import *
from ctypes.wintypes import DWORD
from config.write_output import print_output, print_debug
from config.constant import *
from config.header import Header
from config.moduleInfo import ModuleInfo

memcpy = cdll.msvcrt.memcpy
LocalFree = windll.kernel32.LocalFree
CryptUnprotectData = windll.crypt32.CryptUnprotectData
CRYPTPROTECT_UI_FORBIDDEN = 0x01

class DATA_BLOB(Structure):
	_fields_ = [
		('cbData', DWORD),
		('pbData', POINTER(c_char))
	]

class Network(ModuleInfo):
	def __init__(self):
		options = {'command': '-n', 'action': 'store_true', 'dest': 'network', 'help': 'generic network credentials'}
		ModuleInfo.__init__(self, 'Generic Network', 'windows', options)
	
	def getData(self, blobOut):
		cbData = int(blobOut.cbData)
		pbData = blobOut.pbData
		buffer = c_buffer(cbData)
		memcpy(buffer, pbData, cbData)
		LocalFree(pbData);
		return buffer.raw

	def get_creds(self):
		try:
			creds = win32cred.CredEnumerate(None, 0)
			return creds
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return None

	def get_entropy(self):
		entropy = 'abe2869f-9b47-4cd9-a358-c22904dba7f7\0'
		
		s = ''
		for c in entropy:
			s += struct.pack('<h', ord(c) << 2)
			entropy = s
		return s

	def Win32CryptUnprotectData(self, cipherText, entropy):
		bufferIn = c_buffer(cipherText, len(cipherText))
		blobIn = DATA_BLOB(len(cipherText), bufferIn)
		bufferEntropy = c_buffer(entropy, len(entropy))
		blobEntropy = DATA_BLOB(len(entropy), bufferEntropy)
		blobOut = DATA_BLOB()

		if CryptUnprotectData(byref(blobIn), None, byref(blobEntropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(blobOut)):
			return self.getData(blobOut)
		else:
			return 'failed'

	def run(self):
		# print title
		Header().title_info('Generic Network')
		
		os_plateform = platform.release()
		
		a = self.get_creds()
		pwd = ''
		pwdFound = []
		if a:
			for i in a:
				values = {}
				if i['Type'] == win32cred.CRED_TYPE_GENERIC:
					cipher_text = i['CredentialBlob']
					
					if os_plateform == 'XP':
						pwd = self.Win32CryptUnprotectData(cipher_text, self.get_entropy())
					else:
						pwd = cipher_text
					
					if pwd != 'failed':
						targetName = i['TargetName'].replace('Microsoft_WinInet_', '')
						values['TargetName'] = targetName 
							
						if os_plateform == 'XP':
							t = targetName.split('/')
							targetName = t[0]
						
						if i['UserName'] is not None:
							values['Username'] = i['UserName']
						
						try:
							values['Password'] = pwd.decode('utf16')
						except Exception,e:
							print_debug('DEBUG', '{0}'.format(e)) 
							values['INFO'] = 'Error decoding the password'
						
						pwdFound.append(values)
			
			# print the results
			print_output("Generic Network", pwdFound)
			
		else:
			print_debug('INFO', 'No credentials listed with the enum cred function')



