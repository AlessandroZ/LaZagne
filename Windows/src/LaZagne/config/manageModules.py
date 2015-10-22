# browsers
from softwares.browsers.mozilla import Mozilla
from softwares.browsers.chrome import Chrome
from softwares.browsers.opera import Opera
from softwares.browsers.ie import IE
# windows
from softwares.windows.network import Network
from softwares.windows.dot_net import Dot_net
from softwares.windows.secrets import Secrets
# sysadmin
from softwares.sysadmin.filezilla import Filezilla
from softwares.sysadmin.cyberduck import Cyberduck
from softwares.sysadmin.puttycm import Puttycm
from softwares.sysadmin.winscp import WinSCP
from softwares.sysadmin.coreftp import CoreFTP
from softwares.sysadmin.ftpnavigator import FtpNavigator
# svn
from softwares.svn.tortoise import Tortoise
# chats
from softwares.chats.skype import Skype
from softwares.chats.pidgin import Pidgin
from softwares.chats.jitsi import Jitsi
# wifi
from softwares.wifi.wifi import Wifi
from softwares.wifi.wifipass import WifiPass
# mails
from softwares.mails.outlook import Outlook
# databases
from softwares.databases.sqldeveloper import SQLDeveloper
from softwares.databases.squirrel import Squirrel
from softwares.databases.dbvis import Dbvisualizer
# games
from softwares.games.roguestale import RoguesTale
from softwares.games.kalypsomedia import KalypsoMedia
from softwares.games.galconfusion import GalconFusion
from softwares.games.turba import Turba

def get_categories():
	category = {
		'chats': {'help': 'Chat clients supported'},
		'sysadmin': {'help': 'SCP/SSH/FTP/FTPS clients supported'},
		'database': {'help': 'SQL clients supported'},
		'svn': {'help': 'SVN clients supported'},
		'mails': {'help': 'Email clients supported'},
		'wifi': {'help': 'Wifi'},
		'browsers': {'help': 'Web browsers supported'},
		'windows': {'help': 'Windows credentials (credential manager, etc.)'},
		'games': {'help': 'Games etc.'}
	}
	return category
	
def get_modules():
	moduleNames = [
		Dbvisualizer(), 
		Dot_net(),
		Chrome(), 
		CoreFTP(), 
		Cyberduck(),
		Filezilla(), 
		FtpNavigator(), 
		IE(),
		GalconFusion(),
		Jitsi(),
		KalypsoMedia(),
		Mozilla(),
		Network(), 
		Opera(),
		Outlook(),
		Pidgin(),
		Puttycm(),
      RoguesTale(),
		Tortoise(), 
		Secrets(), 
		Skype(), 
		SQLDeveloper(), 
		Squirrel(),
		Turba(),
		Wifi(), 
		WifiPass(),
		WinSCP()
	]
	return moduleNames
