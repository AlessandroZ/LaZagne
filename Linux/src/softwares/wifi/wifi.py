from ConfigParser import RawConfigParser
from config.header import Header
from config.write_output import print_debug, print_output
from config.moduleInfo import ModuleInfo
import os

class Wifi(ModuleInfo):
	def __init__(self):
		options = {'command': '-wi', 'action': 'store_true', 'dest': 'wifi', 'help': 'Network Manager - Need root Privileges'}
		ModuleInfo.__init__(self, 'wifi', 'wifi', options)

	def run(self):
		# print the title
		Header().title_info('Wifi (from Network Manager)')
		
		directory = '/etc/NetworkManager/system-connections'
		if os.path.exists(directory):
			if os.getuid() != 0:
				print_debug('INFO', 'You need more privileges (run it with sudo)\n')
			
			wireless_ssid = [ f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory,f))]
			
			pwdFound = []
			for w in wireless_ssid:
				cp = RawConfigParser()
				cp.read(os.path.join(directory, w))
				values = {}
				
				values['SSID'] = w
				if cp.sections():
					for section in cp.sections():
						if 'wireless' in section:
							for i in cp.items(section):
								values[i[0]] = i[1]
				
				# write credentials into a text file
				if len(values) != 0:
					pwdFound.append(values)
			
			# print the results
			print_output('Wifi', pwdFound)
		else:
			print_debug('WARNING', 'the path "%s" does not exist' %(directory))
