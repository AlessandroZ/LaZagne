#!/usr/bin/env python
# -*- coding: utf-8 -*- 
# keyring
from lazagne.softwares.wallet.kde import Kde
from lazagne.softwares.wallet.libsecret import Libsecret
# browsers
from lazagne.softwares.browsers.mozilla import firefox_browsers
from lazagne.softwares.browsers.opera import Opera
from lazagne.softwares.browsers.chrome import Chrome
# sysadmin
from lazagne.softwares.sysadmin.filezilla import Filezilla
from lazagne.softwares.sysadmin.env_variable import Env_variable
from lazagne.softwares.sysadmin.shadow import Shadow
from lazagne.softwares.sysadmin.aws import Aws
from lazagne.softwares.sysadmin.ssh import Ssh
from lazagne.softwares.sysadmin.docker import Docker
from lazagne.softwares.sysadmin.cli import Cli
# chats
from lazagne.softwares.chats.pidgin import Pidgin
# mails
from lazagne.softwares.mails.clawsmail import ClawsMail
from lazagne.softwares.mails.thunderbird import Thunderbird
# wifi
from lazagne.softwares.wifi.wifi import Wifi
from lazagne.softwares.wifi.wpa_supplicant import Wpa_supplicant
# databases
from lazagne.softwares.databases.squirrel import Squirrel
from lazagne.softwares.databases.dbvis import DbVisualizer
from lazagne.softwares.databases.sqldeveloper import SQLDeveloper
# memory
try:
	from lazagne.softwares.memory.mimipy import Mimipy
except:
	pass

try:
	from lazagne.softwares.memory.memorydump import MemoryDump
except:
	pass

def get_categories():
	category = {
		'chats'		: {'help': 'Chat clients supported'},
		'sysadmin'	: {'help': 'SCP/SSH/FTP/FTPS clients supported'},
		'databases'	: {'help': 'SQL clients supported'},
		'mails'		: {'help': 'Email clients supported'},
		'memory'	: {'help': 'Retrieve passwords from memory'},
		'wifi'		: {'help': 'Wifi'},
		'browsers'	: {'help': 'Web browsers supported'},
		'wallet'	: {'help': 'Windows credentials (credential manager, etc.)'}
	}
	return category

def get_modules():
	moduleNames = [
		ClawsMail(),
		Thunderbird(),
		DbVisualizer(),
		Env_variable(),
		Filezilla(),
		# Mozilla(),
		Opera(),
		Chrome(),
		Pidgin(),
		Shadow(),
        Aws(),
        Docker(),
		Ssh(),
		Cli(),
		SQLDeveloper(),
		Squirrel(),
		Wifi(),
		Wpa_supplicant(),
		Kde(),
		Libsecret()
	]

	try:
		moduleNames.append(Mimipy())
	except:
		pass

	# very long to execute
	# try:
	# 	moduleNames.append(MemoryDump())
	# except:
	# 	pass

	return moduleNames + firefox_browsers
