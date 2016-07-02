# keyring
from softwares.wallet.gnome import Gnome
from softwares.wallet.kde import kde
# browsers
from softwares.browsers.mozilla import Mozilla
from softwares.browsers.opera import Opera
# sysadmin
from softwares.sysadmin.filezilla import Filezilla
from softwares.sysadmin.env_variable import Env_variable
from softwares.sysadmin.shadow import Shadow
# chats
from softwares.chats.pidgin import Pidgin
from softwares.chats.jitsi import Jitsi
# mails
from softwares.mails.clawsmail import ClawsMail
# wifi
from softwares.wifi.wifi import Wifi
from softwares.wifi.wpa_supplicant import Wpa_supplicant
# databases
from softwares.databases.squirrel import Squirrel
from softwares.databases.dbvis import DbVisualizer
from softwares.databases.sqldeveloper import SQLDeveloper

def get_categories():
	category = {
		'chats': {'help': 'Chat clients supported'},
		'sysadmin': {'help': 'SCP/SSH/FTP/FTPS clients supported'},
		'database': {'help': 'SQL clients supported'},
		'mails': {'help': 'Email clients supported'},
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
		Opera(),
		Pidgin(),
		Shadow(),
		SQLDeveloper(),
		Squirrel(),
		Wifi(),
		Wpa_supplicant(),
		kde()
	]
	return moduleNames
