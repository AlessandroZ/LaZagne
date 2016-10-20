from ConfigParser import RawConfigParser
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
import os

class Wifi(ModuleInfo):
	def __init__(self):
		options = {'command': '-wi', 'action': 'store_true', 'dest': 'wifi', 'help': 'Network Manager - Need root Privileges'}
		ModuleInfo.__init__(self, 'wifi', 'wifi', options)

	def run(self, software_name = None):
		directory = '/etc/NetworkManager/system-connections'
		if os.path.exists(directory):
			if os.getuid() != 0:
				print_debug('INFO', 'You need more privileges (run it with sudo)\n')
			
			wireless_ssid = [ f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory,f))]
			pwdFound = []
			for w in wireless_ssid:
				cp = RawConfigParser()
				cp.read(os.path.join(directory, w))
				values = {'SSID': w}
				try:
					values['Password'] = cp.get('wifi-security', 'psk')
					pwdFound.append(values)
				except:
					pass
			
			return pwdFound
		else:
			print_debug('WARNING', 'the path "%s" does not exist' %(directory))
