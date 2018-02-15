# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
from subprocess import Popen, PIPE
import binascii
import os

class Wifi(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'Wifi', 'wifi', dpapi_used=True)
	
	def run(self, software_name=None):

		directory = os.path.join(constant.profile['ALLUSERSPROFILE'], u'Microsoft\Wlansvc\Profiles\Interfaces')

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
										
										# need to have system privilege, to use this technic
										password = Win32CryptUnprotectData(binary_string)
										if not password: 
											print_debug('DEBUG', '[!] Try using netsh method')
											process 		= Popen(['netsh.exe', 'wlan', 'show', 'profile', '{SSID}'.format(SSID=values['SSID']), 'key=clear'], stdout=PIPE, stderr=PIPE)
											stdout, stderr 	= process.communicate()
											st 				= stdout.split('-------------')[4].split('\n')[6]
											password 		= st.split(':')[1].strip()
										
										values['Password'] 	= password
										passwordFound = True
									except:
										values['INFO'] = '[!] Password not found.'
							
							if values:
								pwdFound.append(values)	
			return pwdFound