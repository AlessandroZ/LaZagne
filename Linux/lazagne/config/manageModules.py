# keyring
from lazagne.softwares.wallet.gnome import Gnome
from lazagne.softwares.wallet.kde import kde
from lazagne.softwares.wallet.libsecret import libsecret
# browsers
from lazagne.softwares.browsers.mozilla import Mozilla
from lazagne.softwares.browsers.opera import Opera
# sysadmin
from lazagne.softwares.sysadmin.filezilla import Filezilla
from lazagne.softwares.sysadmin.env_variable import Env_variable
from lazagne.softwares.sysadmin.shadow import Shadow
from lazagne.softwares.sysadmin.aws import Aws
from lazagne.softwares.sysadmin.docker import Docker
# chats
from lazagne.softwares.chats.pidgin import Pidgin
from lazagne.softwares.chats.jitsi import Jitsi
# mails
from lazagne.softwares.mails.clawsmail import ClawsMail
# wifi
from lazagne.softwares.wifi.wifi import Wifi
from lazagne.softwares.wifi.wpa_supplicant import Wpa_supplicant
# databases
from lazagne.softwares.databases.squirrel import Squirrel
from lazagne.softwares.databases.dbvis import DbVisualizer
from lazagne.softwares.databases.sqldeveloper import SQLDeveloper
# memory
from lazagne.softwares.memory.mimipy import Mimipy
from lazagne.softwares.memory.memorydump import MemoryDump

def get_categories():
	category = {
		'chats': {'help': 'Chat clients supported'},
		'sysadmin': {'help': 'SCP/SSH/FTP/FTPS clients supported'},
		'database': {'help': 'SQL clients supported'},
		'mails': {'help': 'Email clients supported'},
		'memory': {'help': 'Retrieve passwords from memory'},
		'wifi': {'help': 'Wifi'},
		'browsers': {'help': 'Web browsers supported'},
		'wallet': {'help': 'Windows credentials (credential manager, etc.)'}
	}
	return category

def get_modules():
	moduleNames = [
		ClawsMail(),
		DbVisualizer(),
		Env_variable(),
		Filezilla(),
		Gnome(),
		Jitsi(),
		Mozilla(),
		# MemoryDump(),	 # very long to execute
		Mimipy(),
		Opera(),
		Pidgin(),
		Shadow(),
        Aws(),
        Docker(),
		SQLDeveloper(),
		Squirrel(),
		Wifi(),
		Wpa_supplicant(),
		kde(),
		libsecret()
	]
	return moduleNames
