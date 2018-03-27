# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.module_info import ModuleInfo
from lazagne.config.dpapi_structure import *
from lazagne.config.winstructure import *
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
from subprocess import Popen, PIPE
import binascii
import os

class Wifi(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'Wifi', 'wifi', dpapi_used=True)

	def decrypt_using_lsa_secret(self, key):
		"""
		Needs admin priv but will work with all systems
		"""
		if not constant.dpapi:
			constant.dpapi = Decrypt_DPAPI(password=constant.user_password)
		return constant.dpapi.decrypt_wifi_blob(key)

	def decrypt_using_netsh(self, ssid):
		"""
		Does not need admin priv but would work only with english and french systems
		"""
		print_debug('DEBUG', u'[!] Try using netsh method')
		process 		= Popen(['netsh.exe', 'wlan', 'show', 'profile', '{SSID}'.format(SSID=ssid), 'key=clear'], stdout=PIPE, stderr=PIPE)
		stdout, stderr 	= process.communicate()
		for st in stdout.split('\n'):
			if 'key content' in st.lower() or 'contenu de la cl' in st.lower():
				password = st.split(':')[1].strip()
				return password
	
	def run(self, software_name=None):

		if not constant.wifi_password:
			dpapi = constant.dpapi if constant.dpapi is not None else Decrypt_DPAPI(password=constant.user_password)

			interfaces_dir = os.path.join(constant.profile['ALLUSERSPROFILE'], u'Microsoft\Wlansvc\Profiles\Interfaces')

			# for windows Vista or higher
			if os.path.exists(interfaces_dir):

				repository 	= []
				pwdFound 	= []

				for wifi_dir in os.listdir(interfaces_dir):
					if os.path.isdir(os.path.join(interfaces_dir, wifi_dir)):
						
						repository = os.path.join(interfaces_dir, wifi_dir)
						for file in os.listdir(repository):
							values = {}
							if os.path.isfile(os.path.join(repository, file)):
								f 		= os.path.join(repository, file)
								tree 	= ET.ElementTree(file=f)
								root 	= tree.getroot()
								xmlns 	=  root.tag.split("}")[0] + '}'
								
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
											password = self.decrypt_using_lsa_secret(key=key)
											if not password:
												password = self.decrypt_using_netsh(ssid=values['SSID'])

											if password:
												values['Password'] = password
											else:
												values['INFO'] = '[!] Password not found.'
										except Exception, e:
											print e
											values['INFO'] = '[!] Password not found.'
								
								if values and values['Authentication'] != 'open':
									pwdFound.append(values)	

				constant.wifi_password = True
				return pwdFound