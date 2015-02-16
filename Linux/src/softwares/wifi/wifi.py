from ConfigParser import RawConfigParser
from config.header import Header
from config.write_output import print_debug, print_output
import os

class Wifi():
	def retrieve_password(self):
		# print the title
		Header().title_debug('Wifi (from Network Manager)')
		
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
			print_debug('ERROR', 'the path "%s" does not exist' %(directory))
