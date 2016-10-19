#######################
#
# By rpesche
#
#######################

from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
import re
import os

class Wpa_supplicant(ModuleInfo):

	filestr = '/etc/wpa_supplicant/wpa_supplicant.conf'

	def __init__(self):
		options = {'command': '-wp', 'action': 'store_true', 'dest': 'wpa_supplicant', 'help': 'WPA Supplicant - Need root Privileges'}
		ModuleInfo.__init__(self, 'wpa_supplicant', 'wifi', options)

	def parse_file_network(self, fd):
		password=None
		ssid=None

		for line in fd:
			if re.match('^[ \t]*ssid=', line):
				ssid=(line.split("\"")[1])
			if re.match('^[ \t]*psk=', line):
				password=line.split("\"")[1]
			if re.match('^[ \t]*password=', line):
				password=line.split("\"")[1]
			if re.match('^[ \t]*}', line):
				return (ssid, password)

	def parse_file(self):
		pwdFound = []
		
		fd = None
		try:
			fd = open(self.filestr)
		except Exception, e: 
			print_debug('DEBUG', '{0}'.format(e))
			print_debug('INFO', 'Could not open the file: %s ' % self.filestr)

		if fd:
			for line in fd:
				if "network=" in line:
					values = {}
					(ssid,password) = self.parse_file_network(fd)
					if ssid and password:
						values['Password'] = password
						values['SSID'] = ssid
						pwdFound.append(values)
			fd.close()
		return pwdFound;

	def check_file_access(self):
		if not os.path.exists(self.filestr):
			print_debug('WARNING', 'The path "%s" does not exist' %(self.filestr))
			return -1
		return 0

	def run(self, software_name = None):
		if self.check_file_access():
			return

		# check root access
		if os.getuid() != 0:
			print_debug('INFO', 'You need more privileges (run it with sudo)\n')
			return 

		pwdFound = self.parse_file()
		return pwdFound
