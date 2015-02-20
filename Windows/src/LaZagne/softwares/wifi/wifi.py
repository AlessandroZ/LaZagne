from config.write_output import print_output, print_debug
from config.header import Header
from config.get_system_priv import get_system_priv
from ctypes import *
import time, tempfile
from ConfigParser import RawConfigParser
import os

class Wifi():
	
	def retrieve_password(self):
		
		# print title
		Header().title_debug('Wifi')
		
		if not windll.Shell32.IsUserAnAdmin():
			print_debug('ERROR', '[!] This script should be run as admin!')
			return
		else:
			
			if 'ALLUSERSPROFILE' in os.environ:
				directory = os.environ['ALLUSERSPROFILE'] + os.sep + 'Microsoft\Wlansvc\Profiles\Interfaces'
			else:
				print_debug('ERROR', 'Environment variable (ALLUSERSPROFILE) has not been found.')
				return
			
			if not os.path.exists(directory):
				print_debug('INFO', 'No credentials found.\nFile containing passwords not found:\n%s' % directory)
				return
				
			try:
				print_debug('INFO', '[!] Trying to elevate our privilege')
				get_system_priv()
				print_debug('INFO', '[!] Elevation ok - Passwords decryption is in progress')
			except:
				print_debug('ERROR', '[!] An error occurs during the privilege elevation process. Wifi passwords have not been decrypted')
			
			time.sleep(5)
			
			# read temp file containing all passwords found
			pwdFound = []
			filepath = tempfile.gettempdir() + os.sep + 'TEMP123A.txt'
			if os.path.exists(filepath):
				cp = RawConfigParser()
				cp.read(filepath)
				for section in cp.sections():
					values = {}
					for c in cp.items(section):
						values[str(c[0])] = str(c[1])
					pwdFound.append(values)
				
				# remove file on the temporary directory
				os.remove(filepath)
				
				# print the results
				print_output("Wifi", pwdFound)
			else:
				print_debug('INFO', 'No passwords found')