import xml.etree.cElementTree as ET
import os
from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
import dbus
from lazagne.config.moduleInfo import ModuleInfo

class Pidgin(ModuleInfo):
	def __init__(self):
		options = {'command': '-p', 'action': 'store_true', 'dest': 'pidgin', 'help': 'pidgin'}
		ModuleInfo.__init__(self, 'pidgin', 'chats', options)
	
	# if pidgin is started, use the api to retrieve all passwords
	def check_if_pidgin_started(self):
		try:
			bus = dbus.SessionBus()
			purple = bus.get_object("im.pidgin.purple.PurpleService","/im/pidgin/purple/PurpleObject","im.pidgin.purple.PurpleInterface")
			acc = purple.PurpleAccountsGetAllActive()
			
			pwdFound = []
			for x in range(len(acc)):
				values = {}
				_acc = purple.PurpleAccountsGetAllActive()[x]
				values['Login'] =  purple.PurpleAccountGetUsername(_acc)
				values['Password'] =  purple.PurpleAccountGetPassword(_acc)
				values['Protocol'] =  purple.PurpleAccountGetProtocolName(_acc)
				pwdFound.append(values)

			# print the results
			return pwdFound
		except:
			# [!] Pidgin is not started :-(
			return False
			

	def run(self, software_name = None):		
		pwdFound = []
		try:
			pwdTab = self.check_if_pidgin_started()
			if pwdTab != False:
				pwdFound = pwdTab
		except:
			pass

		directory = '~/.purple'
		directory = os.path.expanduser(directory)
		
		path = os.path.join(directory, 'accounts.xml')

		if os.path.exists(path):
			tree = ET.ElementTree(file=path)
			
			root = tree.getroot()
			accounts = root.getchildren()
			
			for a in accounts:
				values = {}
				aa = a.getchildren()
				for tag in aa:
					cpt = 0
					if tag.tag == 'name':
						cpt = 1
						values['Login'] = tag.text
					
					if tag.tag == 'password':
						values['Password'] = tag.text
				
				if len(values) != 0:
					pwdFound.append(values)
			
			return pwdFound
		else:
			print_debug('INFO', 'Pidgin not installed.')
		
		
