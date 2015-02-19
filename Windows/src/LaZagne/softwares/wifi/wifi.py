import xml.etree.cElementTree as ET
import os, win32crypt
import binascii
from config.write_output import print_output, print_debug
from config.constant import *
from config.header import Header

class Wifi():
	
	def retrieve_password(self):
		# print title
		Header().title_debug('Wifi')
		
		if 'ALLUSERSPROFILE' in os.environ:
			directory = os.environ['ALLUSERSPROFILE'] + os.sep + 'Microsoft\Wlansvc\Profiles\Interfaces'
		else:
			print_debug('ERROR', 'Environment variable (ALLUSERSPROFILE) has not been found.')
			return
		
		# for windows Vista or higher
		if os.path.exists(directory):
			rep = []
			pwdFound = []
			for repository in os.listdir(directory):
				if os.path.isdir(directory + os.sep + repository):
					
					rep = directory + os.sep + repository
					for file in os.listdir(rep):
						values = {}
						if os.path.isfile(rep + os.sep + file):
							f = rep + os.sep + file
							tree = ET.ElementTree(file=f)
							root = tree.getroot()
							xmlns =  root.tag.split("}")[0] + '}'
							
							iterate = False
							for elem in tree.iter():
								if elem.tag.endswith('SSID'):
									for w in elem:
										if w.tag == xmlns + 'name':
											values['SSID'] = w.text
								
								if elem.tag.endswith('authentication'):
									values['Authentication'] = elem.text
									
								if elem.tag.endswith('protected'):
									values['Protected'] = elem.text
								
								if elem.tag.endswith('keyMaterial'):
									key = elem.text
									try:
										binary_string = binascii.unhexlify(key)
										password = win32crypt.CryptUnprotectData(binary_string, None, None, None, 0)[1]
										values['Password'] = password
									except:
										values['INFO'] = '[!] Password not found. Try with System privileges'
							
							# store credentials
							if len(values) != 0:
								pwdFound.append(values)
			
			# print the results
			print_output("Wifi", pwdFound)
		else:
			print_debug('INFO', 'No credentials found.\nFile containing passwords not found:\n%s' % directory)
		