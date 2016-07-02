#!/usr/bin/env python
import os
from config.header import Header
from config.write_output import print_debug, print_output
from config.moduleInfo import ModuleInfo

class Gnome(ModuleInfo):
	def __init__(self):
		options = {'command': '-g', 'action': 'store_true', 'dest': 'gnomeKeyring', 'help': 'Gnome Keyring'}
		ModuleInfo.__init__(self, 'gnomeKeyring', 'wallet', options)
	
	def run(self):
		# print the title
		Header().title_info('Gnome keyring')
		
		if os.getuid() == 0:
			print_debug('WARNING', 'Do not run it with root privileges)\n')
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
							
							if attr.has_key('server'):
								values["Server"] = attr['server']
							
							if attr.has_key('protocol'):
								values["Protocol"] = attr['protocol']
							
							if attr.has_key('unique'):
								values["Unique"] = attr['unique']
								
							if attr.has_key('domain'):
								values["Domain"] = attr['domain']
							
							if attr.has_key('origin_url'):
								values["Origin_url"] = attr['origin_url']
							
							if attr.has_key('username_value'):
								values["Username"] = attr['username_value']
							
							if attr.has_key('user'):
								values["Username"] = attr['user']
							
							if item.get_secret():
								values["Password"] = item.get_secret()
							
							# write credentials into a text file
							if len(values) != 0:
								pwdFound.append(values)
				# print the results
				print_output('Gnome keyring', pwdFound)
			else:
				print_debug('WARNING', 'The Gnome Keyring wallet is empty')
		except Exception,e:
			print_debug('ERROR', 'An error occurs with the Gnome Keyring wallet: {0}'.format(e))
		
