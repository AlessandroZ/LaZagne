from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
import _winreg

# Password are stored in cleartext on old system (< 2008 R2 and < Win7)
# If enabled on recent system, the password should be visible on the lsa secrets dump (check lsa module output)

class Autologon(ModuleInfo):
	def __init__(self):
		options = {'command': '--autologon', 'action': 'store_true', 'dest': 'autologon', 'help': 'Windows autologon'}
		ModuleInfo.__init__(self, 'Autologon', 'windows', options, cannot_be_impersonate_using_tokens=True)

	def run(self, software_name = None):		
		pwdFound = []
		try:
			hkey = OpenKey(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
			if int(_winreg.QueryValueEx(hkey, 'AutoAdminLogon')[0]) == 1:
				print_debug('INFO', 'Autologin enabled')

				keys = {
					'DefaultDomainName' 	: '', 
					'DefaultUserName'		: '', 
					'DefaultPassword'		: '', 
					'AltDefaultDomainName'	: '', 
					'AltDefaultUserName'	: '', 
					'AltDefaultPassword'	: '', 
				}

				toRemove = []
				for k in keys:
					try:
						keys[k] = str(_winreg.QueryValueEx(hkey, k)[0])
					except:
						toRemove.append(k) 

				for r in toRemove:
					keys.pop(r)

				if keys:
					pwdFound.append(keys)
  
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return

		return pwdFound