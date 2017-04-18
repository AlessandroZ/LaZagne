from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from Crypto.Cipher import AES
import binascii
import _winreg

class CoreFTP(ModuleInfo):
	def __init__(self):
		options = {'command': '-core', 'action': 'store_true', 'dest': 'coreftp', 'help': 'coreftp'}
		ModuleInfo.__init__(self, 'coreftp', 'sysadmin', options)
		
		self._secret = "hdfzpysvpzimorhk"

	def decrypt(self, hex):
		encoded = binascii.unhexlify(hex)
		secret = self._secret
		BLOCK_SIZE = 16
		mode = AES.MODE_ECB
		cipher = AES.new(secret,mode)
		return cipher.decrypt(encoded).split('\x00')[0]
	
	def get_key_info(self):
		try:
			key = _winreg.OpenKey(HKEY_CURRENT_USER, 'Software\\FTPware\\CoreFTP\\Sites')
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return False
			
		num_profiles = _winreg.QueryInfoKey(key)[0]
		pwdFound = []
		for n in range(num_profiles):
			name_skey = _winreg.EnumKey(key, n)
			
			skey = _winreg.OpenKey(key, name_skey)
			num = _winreg.QueryInfoKey(skey)[1]
			
			values = {}
			for nn in range(num):
				k = _winreg.EnumValue(skey, nn)
				if k[0] == 'Host':
					values['Host'] = k[1]
				if k[0] == 'Port':
					values['Port'] = k[1]
				if k[0] == 'User':
					values['Login'] = k[1]
					pwdFound.append(values)
				if k[0] == 'PW':
					try:
						values['Password'] = self.decrypt(k[1])
					except Exception,e:
						print_debug('DEBUG', '{0}'.format(e))
						values['Password'] = 'N/A'

			_winreg.CloseKey(skey)
		_winreg.CloseKey(key)
		
		return pwdFound
		
	def run(self, software_name = None):	
		pwdFound = self.get_key_info()
		if not pwdFound:
			print_debug('INFO', 'CoreFTP not installed')
		else:
			return pwdFound
