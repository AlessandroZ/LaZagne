# browsers
from lazagne.softwares.browsers.mozilla import Mozilla
from lazagne.softwares.browsers.chrome import Chrome
from lazagne.softwares.browsers.opera import Opera
from lazagne.softwares.browsers.ie import IE
# windows
# from lazagne.softwares.windows.system import System
from lazagne.softwares.windows.credman import Credman
from lazagne.softwares.windows.vault import Vault
from lazagne.softwares.windows.cachedump import Cachedump
from lazagne.softwares.windows.hashdump import Hashdump
from lazagne.softwares.windows.lsa_secrets import LSASecrets

# sysadmin
from lazagne.softwares.sysadmin.filezilla import Filezilla
from lazagne.softwares.sysadmin.cyberduck import Cyberduck
from lazagne.softwares.sysadmin.puttycm import Puttycm
from lazagne.softwares.sysadmin.winscp import WinSCP
from lazagne.softwares.sysadmin.coreftp import CoreFTP
from lazagne.softwares.sysadmin.ftpnavigator import FtpNavigator
from lazagne.softwares.sysadmin.apachedirectorystudio import ApacheDirectoryStudio
from lazagne.softwares.sysadmin.opensshforwindows import OpenSSHForWindows
# svn
from lazagne.softwares.svn.tortoise import Tortoise
# git
from lazagne.softwares.git.gitforwindows import GitForWindows
# maven
from lazagne.softwares.maven.mavenrepositories import MavenRepositories
# chats
from lazagne.softwares.chats.skype import Skype
from lazagne.softwares.chats.pidgin import Pidgin
from lazagne.softwares.chats.jitsi import Jitsi
# wifi
from lazagne.softwares.wifi.wifi import Wifi
# mails
from lazagne.softwares.mails.outlook import Outlook
# databases
from lazagne.softwares.databases.sqldeveloper import SQLDeveloper
from lazagne.softwares.databases.squirrel import Squirrel
from lazagne.softwares.databases.dbvis import Dbvisualizer
from lazagne.softwares.databases.robomongo import Robomongo
# games
from lazagne.softwares.games.roguestale import RoguesTale
from lazagne.softwares.games.kalypsomedia import KalypsoMedia
from lazagne.softwares.games.galconfusion import GalconFusion
from lazagne.softwares.games.turba import Turba
# memory
from lazagne.softwares.memory.keepass import Keepass
from lazagne.softwares.memory.memorydump import MemoryDump
# php
from lazagne.softwares.php.composer import Composer

def get_categories():
	category = {
		'chats': {'help': 'Chat clients supported'},
		'sysadmin': {'help': 'SCP/SSH/FTP/FTPS clients supported'},
		'database': {'help': 'SQL/NoSQL clients supported'},
		'svn': {'help': 'SVN clients supported'},
		'git': {'help': 'GIT clients supported'},
		'maven': {'help': 'Maven java build tool'},
		'php': {'help': 'PHP build tool'},
		'mails': {'help': 'Email clients supported'},
		'memory': {'help': 'Retrieve passwords from memory'},
		'wifi': {'help': 'Wifi'},
		'browsers': {'help': 'Web browsers supported'},
		'windows': {'help': 'Windows credentials (credential manager, etc.)'},
		'games': {'help': 'Games etc.'}
	}
	return category
	
def get_modules():
	moduleNames = [
		ApacheDirectoryStudio(),
		Dbvisualizer(), 
		Chrome(), 
		CoreFTP(), 
		Cyberduck(),
		Filezilla(), 
		FtpNavigator(), 
		GalconFusion(),
		GitForWindows(),
		IE(),
		Jitsi(),
		KalypsoMedia(),
		MavenRepositories(),
		MemoryDump(),			# retrieve browers and keepass passwords
		Keepass(),				# should be launched after memory dump
		Mozilla(),
		Composer(),
		Credman(),
		OpenSSHForWindows(), 
		Opera(),
		Outlook(),
		Pidgin(),
		Puttycm(),
		Robomongo(),
      	RoguesTale(),
		Tortoise(), 
		Skype(), 
		SQLDeveloper(), 
		Squirrel(),
		Turba(),
		Vault(),
		Wifi(), 
		WinSCP(),
		Cachedump(),
		Hashdump(),
		LSASecrets()
	]
	return moduleNames
