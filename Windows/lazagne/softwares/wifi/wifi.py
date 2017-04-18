import xml.etree.cElementTree as ET
import os
import binascii
import tempfile, socket
from ctypes import *
from lazagne.config.constant import *
from lazagne.config.WinStructure import *
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.write_output import print_debug

class Wifi(ModuleInfo):
	def __init__(self):
		options = {'command': '-wi', 'action': 'store_true', 'dest': 'wifi', 'help': 'Vista and higher - Need System Privileges'}
		ModuleInfo.__init__(self, 'Wifi', 'wifi', options, need_system_privileges=True)
	
	# used when launched with a system account 
	def run(self, software_name = None):
		# need to be admin privilege, to find passwords
		if not windll.Shell32.IsUserAnAdmin():
			print_debug('WARNING', '[!] This script should be run as admin!')
			return
		else:
			directory = constant.profile['ALLUSERSPROFILE'] + os.sep + 'Microsoft\Wlansvc\Profiles\Interfaces'

			# for windows Vista or higher
			if os.path.exists(directory):
				passwordFound = False
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
											password = Win32CryptUnprotectData(binary_string)
											values['Password'] = password
											passwordFound = True
										except:
											values['INFO'] = '[!] Password not found.'
								
								if values:
									pwdFound.append(values)	
				return pwdFound