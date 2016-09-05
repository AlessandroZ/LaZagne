import win32con, win32api
from lazagne.config.write_output import print_debug
from lazagne.config.constant import *
from lazagne.config.moduleInfo import ModuleInfo

class WinSCP(ModuleInfo):
	def __init__(self):
		self.hash = ''
		self.username = ''
		self.hostname = ''
		
		options = {'command': '-scp', 'action': 'store_true', 'dest': 'winscp', 'help': 'winscp'}
		ModuleInfo.__init__(self, 'winscp', 'sysadmin', options)
	
	# ------------------------------ Getters and Setters ------------------------------
	def get_hash(self):
		return self.hash
	
	def set_hash(self, _hash):
		self.hash = _hash
	
	def get_username(self):
		return self.username
	
	def set_username(self, _username):
		self.username = _username
	
	def get_hostname(self):
		return self.hostname
	
	def set_hostname(self, _hostname):
		self.hostname = _hostname
	
	def decrypt_char(self):
		hash = self.get_hash()
		
		hex_flag = 0xA3
		charset = '0123456789ABCDEF'
		
		if len(hash) > 0:
			unpack1 = charset.find(hash[0])
			unpack1 = unpack1 << 4
			
			unpack2 = charset.find(hash[1])
			result = ~((unpack1 + unpack2) ^ hex_flag) & 0xff
			
			# store the new hash
			self.set_hash(hash[2:])
			
			return result
	
	def check_winscp_installed(self):
		accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
		try:
			key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, 'Software\Martin Prikryl\WinSCP 2\Configuration\Security', 0, accessRead)
			return True
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return False
	
	def check_masterPassword(self):
		accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
		key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, 'Software\Martin Prikryl\WinSCP 2\Configuration\Security', 0, accessRead)
		thisName = str(win32api.RegQueryValueEx(key, 'UseMasterPassword')[0])
		
		if thisName == '0':
			return False
		else:
			return True
	
	def get_logins_info(self):
		accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
		try:
			key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, 'Software\Martin Prikryl\WinSCP 2\Sessions', 0, accessRead)
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return False
		
		num_profiles = win32api.RegQueryInfoKey(key)[0]
		
		pwdFound = []
		for n in range(num_profiles):
			name_skey = win32api.RegEnumKey(key, n)
			
			skey = win32api.RegOpenKey(key, name_skey, 0, accessRead)
			num = win32api.RegQueryInfoKey(skey)[1]
			
			port = ''
			values = {}
			
			for nn in range(num):
				k = win32api.RegEnumValue(skey, nn)
				
				if k[0] == 'HostName':
					self.set_hostname(k[1])
				
				if k[0] == 'UserName':
					self.set_username(k[1])
				
				if k[0] == 'Password':
					self.set_hash(k[1])
				
				if k[0] == 'PortNumber':
					port = str(k[1])
			
			if num != 0:
				if port == '':
					port = '22'
				try:
					password = self.decrypt_password()
					values['Password'] = password
				except Exception,e:
					print_debug('DEBUG', '{0}'.format(e))
				
				values['Hostname'] = self.get_hostname()
				values['Port'] = port
				values['Username'] = self.get_username()
				
				pwdFound.append(values)
		
		return pwdFound
		
	def decrypt_password(self):
		hex_flag = 0xFF
		
		flag = self.decrypt_char()
		if flag == hex_flag:
			self.decrypt_char()
			length = self.decrypt_char()
		else:
			length = flag
		
		ldel = (self.decrypt_char())*2
		
		hash = self.get_hash()
		self.set_hash(hash[ldel: len(hash)])
		
		result = ''
		for ss in range(length):
			
			try:
				result += chr(int(self.decrypt_char()))
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
				pass
		
		if flag == hex_flag:
			key = self.get_username() + self.get_hostname()
			result = result[len(key): len(result)]
		
		return result
	
	# --------- Main function ---------
	def run(self, software_name = None):

		if self.check_winscp_installed():
			if not self.check_masterPassword():
				r = self.get_logins_info()
				if r == False:
					print_debug('INFO', 'WinSCP not installed.')
				else:
					return r
			else:
				print_debug('WARNING', 'A master password is used. Passwords cannot been retrieved')
		else:
			print_debug('INFO', 'WinSCP not installed.')
