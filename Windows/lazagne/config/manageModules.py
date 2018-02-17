# Browsers
from lazagne.softwares.browsers.chrome import Chrome
from lazagne.softwares.browsers.coccoc import CocCoc
from lazagne.softwares.browsers.ie 	import IE
from lazagne.softwares.browsers.mozilla import Mozilla
from lazagne.softwares.browsers.opera import Opera

# Chats
from lazagne.softwares.chats.jitsi import Jitsi
from lazagne.softwares.chats.pidgin import Pidgin
from lazagne.softwares.chats.skype import Skype

# Databases
from lazagne.softwares.databases.dbvis import Dbvisualizer
from lazagne.softwares.databases.squirrel import Squirrel
from lazagne.softwares.databases.sqldeveloper import SQLDeveloper
from lazagne.softwares.databases.robomongo import Robomongo
from lazagne.softwares.databases.postgresql import PostgreSQL

# Games
from lazagne.softwares.games.kalypsomedia import KalypsoMedia
from lazagne.softwares.games.galconfusion import GalconFusion
from lazagne.softwares.games.roguestale import RoguesTale
from lazagne.softwares.games.turba import Turba

# Git
from lazagne.softwares.git.gitforwindows import GitForWindows

# Mails
from lazagne.softwares.mails.outlook import Outlook

# Maven
from lazagne.softwares.maven.mavenrepositories import MavenRepositories

# Memory
from lazagne.softwares.memory.keepass import Keepass
from lazagne.softwares.memory.memorydump import MemoryDump

# Php
from lazagne.softwares.php.composer import Composer

# Svn
from lazagne.softwares.svn.tortoise import Tortoise

# Sysadmin
from lazagne.softwares.sysadmin.apachedirectorystudio import ApacheDirectoryStudio
from lazagne.softwares.sysadmin.coreftp import CoreFTP
from lazagne.softwares.sysadmin.cyberduck import Cyberduck
from lazagne.softwares.sysadmin.filezilla import Filezilla
from lazagne.softwares.sysadmin.ftpnavigator import FtpNavigator
from lazagne.softwares.sysadmin.puttycm import Puttycm
from lazagne.softwares.sysadmin.opensshforwindows import OpenSSHForWindows
from lazagne.softwares.sysadmin.rdpmanager import RDPManager
from lazagne.softwares.sysadmin.unattended import Unattended
from lazagne.softwares.sysadmin.winscp import WinSCP

# Wifi
from lazagne.softwares.wifi.wifi import Wifi

# Windows
from lazagne.softwares.windows.autologon import Autologon
from lazagne.softwares.windows.cachedump import Cachedump
from lazagne.softwares.windows.credman import Credman
from lazagne.softwares.windows.hashdump import Hashdump
from lazagne.softwares.windows.lsa_secrets import LSASecrets
from lazagne.softwares.windows.vault import Vault
from lazagne.softwares.windows.windows_password import WindowsPassword
from lazagne.softwares.windows.creds_files import CredFiles


def get_categories():
	category = {
		'browsers'	: {'help': 'Web browsers supported'},
		'chats'		: {'help': 'Chat clients supported'},
		'databases'	: {'help': 'SQL/NoSQL clients supported'},
		'games'		: {'help': 'Games etc.'},
		'git'		: {'help': 'GIT clients supported'},
		'mails'		: {'help': 'Email clients supported'},
		'maven'		: {'help': 'Maven java build tool'},
		'memory'	: {'help': 'Retrieve passwords from memory'},
		'php'		: {'help': 'PHP build tool'},
		'svn'		: {'help': 'SVN clients supported'},
		'sysadmin'	: {'help': 'SCP/SSH/FTP/FTPS clients supported'},
		'windows'	: {'help': 'Windows credentials (credential manager, etc.)'},
		'wifi'		: {'help': 'Wifi'},
	}
	return category

	
def get_modules():
	moduleNames = [

		# Browser
		Chrome(), 
		CocCoc(),
		IE(),
		Mozilla(),
		Opera(),
		
		# Chats
		Jitsi(),
		Pidgin(),
		Skype(),

		# Databases
		Dbvisualizer(), 
		Squirrel(),
		SQLDeveloper(),
		Robomongo(),
		PostgreSQL(),

		# games
		KalypsoMedia(),
		GalconFusion(),
		RoguesTale(),
		Turba(),

		# Git
		GitForWindows(),

		# Mails
		Outlook(),

		# Maven
		MavenRepositories(),

		# Memory
		Keepass(), 				# retrieve browers and keepass passwords
		MemoryDump(), 			# should be launched after memory dump

		# Php
		Composer(),

		# SVN
		Tortoise(),

		# Sysadmin
		ApacheDirectoryStudio(),
		CoreFTP(),
		Cyberduck(),
		Filezilla(),
		FtpNavigator(), 
		Puttycm(),
		OpenSSHForWindows(),
		RDPManager(),
		Unattended(),
		WinSCP(),

		# Wifi
		Wifi(),

		# Windows
		Autologon(),
		Cachedump(),
		Credman(),
		Hashdump(),
		LSASecrets(), 
		Vault(),
		WindowsPassword(),
		CredFiles(),		 	# should be executed at last
	]
	return moduleNames
