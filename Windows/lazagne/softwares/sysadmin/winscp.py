from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import _winreg

class WinSCP(ModuleInfo):
	def __init__(self):
		self.hash = ''
		self.username = ''
		self.hostname = ''
		
		options = {'command': '-scp', 'action': 'store_true', 'dest': 'winscp', 'help': 'winscp'}
		ModuleInfo.__init__(self, 'winscp', 'sysadmin', options, cannot_be_impersonate_using_tokens=True)
	
	# ------------------------------ Getters and Setters ------------------------------
	def decrypt_char(self):	
		hex_flag = 0xA3
		charset = '0123456789ABCDEF'
		
		if len(self.hash) > 0:
			unpack1 = charset.find(self.hash[0])
			unpack1 = unpack1 << 4
			
			unpack2 = charset.find(self.hash[1])
			result = ~((unpack1 + unpack2) ^ hex_flag) & 0xff
			
			# store the new hash
			self.hash = self.hash[2:]
			
			return result
	
	def check_winscp_installed(self):
		try:
			key = _winreg.OpenKey(HKEY_CURRENT_USER, 'Software\Martin Prikryl\WinSCP 2\Configuration\Security')
			return key
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return False
	
	def check_masterPassword(self, key):
		isMasterPwdUsed = _winreg.QueryValueEx(key, 'UseMasterPassword')[0]
		_winreg.CloseKey(key)
		if str(isMasterPwdUsed) == '0':
			return False
		else:
			return True
	
	def get_logins_info(self):
		try:
			key = _winreg.OpenKey(HKEY_CURRENT_USER, 'Software\Martin Prikryl\WinSCP 2\Sessions')
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return False
		
		pwdFound = []
		num_profiles = _winreg.QueryInfoKey(key)[0]
		for n in range(num_profiles):
			name_skey = _winreg.EnumKey(key, n)		# with win32api.RegEnumKey => color is present / with _winreg.EnumKey not wtf ????
			
			skey = _winreg.OpenKey(key, name_skey)
			num = _winreg.QueryInfoKey(skey)[1]
			
			port = ''
			values = {}
			
			for nn in range(num):
				k = _winreg.EnumValue(skey, nn)
				
				if k[0] == 'HostName':
					self.hostname = k[1]
				
				if k[0] == 'UserName':
					self.username = k[1]
				
				if k[0] == 'Password':
					self.hash = k[1]
				
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
				
				values['URL'] = self.hostname
				values['Port'] = port
				values['Login'] = self.username
				
				pwdFound.append(values)

			_winreg.CloseKey(skey)
		_winreg.CloseKey(key)

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
		self.hash = self.hash[ldel: len(self.hash)]
		
		result = ''
		for ss in range(length):
			
			try:
				result += chr(int(self.decrypt_char()))
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
				pass
		
		if flag == hex_flag:
			key = self.username + self.hostname
			result = result[len(key): len(result)]
		
		return result
	
	# --------- Main function ---------
	def run(self, software_name = None):
		k = self.check_winscp_installed()
		if k:
			if not self.check_masterPassword(k):
				r = self.get_logins_info()
				if r == False:
					print_debug('INFO', 'WinSCP not installed.')
				else:
					return r
			else:
				print_debug('WARNING', 'A master password is used. Passwords cannot been retrieved')
		else:
			print_debug('INFO', 'WinSCP not installed.')
