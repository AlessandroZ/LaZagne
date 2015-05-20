import binascii
from Crypto.Cipher import AES
import win32con, win32api
from config.write_output import print_output, print_debug
from config.header import Header
from config.moduleInfo import ModuleInfo

class CoreFTP(ModuleInfo):
	def __init__(self):
		options = {'command': '-core', 'action': 'store_true', 'dest': 'coreftp', 'help': 'coreftp'}
		ModuleInfo.__init__(self, 'coreftp', 'sysadmin', options)
	
	def get_secret(self):
		return "hdfzpysvpzimorhk"
	
	def decrypt(self, hex):
		encoded = binascii.unhexlify(hex)
		secret = self.get_secret()
		BLOCK_SIZE = 16
		mode = AES.MODE_ECB
		cipher=AES.new(secret,mode)
		return cipher.decrypt(encoded).split('\x00')[0]
	
	def get_key_info(self):
		accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
		try:
			key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, 'Software\\FTPware\\CoreFTP\\Sites', 0, accessRead)
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return False
			
		num_profiles = win32api.RegQueryInfoKey(key)[0]
		pwdFound = []
		for n in range(num_profiles):
			name_skey = win32api.RegEnumKey(key, n)
			
			skey = win32api.RegOpenKey(key, name_skey, 0, accessRead)
			num = win32api.RegQueryInfoKey(skey)[1]
			
			values = {}
			for nn in range(num):
				k = win32api.RegEnumValue(skey, nn)
				if k[0] == 'Host':
					values['Host'] = k[1]
				if k[0] == 'Port':
					values['Port'] = k[1]
				if k[0] == 'User':
					values['User'] = k[1]
					pwdFound.append(values)
				if k[0] == 'PW':
					try:
						values['Password'] = self.decrypt(k[1])
					except Exception,e:
						print_debug('DEBUG', '{0}'.format(e))
						values['Password'] = 'N/A'
		# print the results
		print_output('CoreFTP', pwdFound)
		
	def run(self):
		# print title
		Header().title_info('CoreFTP')
		
		if self.get_key_info() == False:
			print_debug('INFO', 'CoreFTP not installed')
