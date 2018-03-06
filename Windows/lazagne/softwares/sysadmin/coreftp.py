# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.winstructure import *
from Crypto.Cipher import AES
import binascii
import _winreg

class CoreFTP(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'coreftp', 'sysadmin')
		
		self._secret = "hdfzpysvpzimorhk"

	def decrypt(self, hex):
		encoded		= binascii.unhexlify(hex)
		secret 		= self._secret
		BLOCK_SIZE 	= 16
		mode 		= AES.MODE_ECB
		cipher 		= AES.new(secret, mode)
		return cipher.decrypt(encoded).split('\x00')[0]
	
	def run(self, software_name=None):	
		key 		= None
		pwdFound 	= []
		try:
			key = OpenKey(HKEY_CURRENT_USER, 'Software\\FTPware\\CoreFTP\\Sites')
		except Exception,e:
			print_debug('DEBUG', str(e))

		if key:	
			num_profiles = _winreg.QueryInfoKey(key)[0]
			for n in range(num_profiles):
				name_skey 	= _winreg.EnumKey(key, n)
				skey 		= OpenKey(key, name_skey)
				num 		= _winreg.QueryInfoKey(skey)[1]
				values 		= {}
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
							print_debug('DEBUG', str(e))
							values['Password'] = 'N/A'

				_winreg.CloseKey(skey)
			_winreg.CloseKey(key)
			
			return pwdFound
