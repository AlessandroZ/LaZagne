import win32api, win32con, win32crypt
from config.write_output import print_output, print_debug
from config.constant import *
from config.header import Header

class Outlook():
	
	def retrieve_password(self):
		# print title
		Header().title_debug('Outlook')
		
		accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
		keyPath = 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook'
		
		try:
			hkey = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, keyPath, 0, accessRead)
		except:
			print_debug('ERROR', 'Outlook not installed.\nAn error occurs retrieving the registry key.\nKey = %s' % keyPath)
			return

		num = win32api.RegQueryInfoKey(hkey)[0]
		pwdFound = []
		for x in range(0, num):
			name = win32api.RegEnumKey(hkey, x)
			skey = win32api.RegOpenKey(hkey, name, 0, accessRead)
			
			num_skey = win32api.RegQueryInfoKey(skey)[0]
			if num_skey != 0:
				for y in range(0, num_skey):
					name_skey = win32api.RegEnumKey(skey, y)
					sskey = win32api.RegOpenKey(skey, name_skey, 0, accessRead)
					num_sskey = win32api.RegQueryInfoKey(sskey)[1]
					
					for z in range(0, num_sskey):
						k = win32api.RegEnumValue(sskey, z)
						if 'password' in k[0].lower():
							values = self.retrieve_info(sskey, name_skey)
							# write credentials into a text file
							if len(values) != 0:
								pwdFound.append(values)
			
			# print the results
			print_output("Outlook", pwdFound)
		

	def retrieve_info(self, hkey, name_key):
		values = {}
		num = win32api.RegQueryInfoKey(hkey)[1]
		for x in range(0, num):
			k = win32api.RegEnumValue(hkey, x)
			if 'password' in k[0].lower():
				try:
					password = win32crypt.CryptUnprotectData(k[1][1:], None, None, None, 0)[1]
					values[k[0]] = password.decode('utf16')
				except:
					values[k[0]] = 'N/A'
					pass
			else:
				try:
					values[k[0]] = str(k[1]).decode('utf16')
				except:
					values[k[0]] = str(k[1])
		return values


