#!/usr/bin/env python
import os
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo

class Gnome(ModuleInfo):
	def __init__(self):
		options = {'command': '-g', 'action': 'store_true', 'dest': 'gnomeKeyring', 'help': 'Gnome Keyring'}
		ModuleInfo.__init__(self, 'gnomeKeyring', 'wallet', options)
	
	def run(self, software_name = None):		
		if os.getuid() == 0:
			print_debug('WARNING', 'Do not run it with root privileges\n')
			return
		try:
			import gnomekeyring
			if len(gnomekeyring.list_keyring_names_sync()) > 0:
				
				pwdFound = []
				for keyring in gnomekeyring.list_keyring_names_sync():
					for id in gnomekeyring.list_item_ids_sync(keyring):
						values = {}
						item = gnomekeyring.item_get_info_sync(keyring, id)
						attr = gnomekeyring.item_get_attributes_sync(keyring, id)
						
						if attr:
							if item.get_display_name():
								values["Item"] = item.get_display_name()
							
							if 'server' in attr:
								values["Host"] = attr['server']
							
							if 'protocol' in attr:
								values["Protocol"] = attr['protocol']
							
							if 'unique' in attr:
								values["Unique"] = attr['unique']
								
							if 'domain' in attr:
								values["Domain"] = attr['domain']
							
							if 'origin_url' in attr:
								values["URL"] = attr['origin_url']
							
							if 'username_value' in attr:
								values["Login"] = attr['username_value']
							
							if 'user' in attr:
								values["User"] = attr['user']
							
							if item.get_secret():
								values["Password"] = item.get_secret()
							
							# write credentials into a text file
							if len(values) != 0:
								pwdFound.append(values)
				return pwdFound
			else:
				print_debug('WARNING', 'The Gnome Keyring wallet is empty')
		except Exception as e:
			print_debug('ERROR', 'An error occurs with the Gnome Keyring wallet: {0}'.format(e))
		
