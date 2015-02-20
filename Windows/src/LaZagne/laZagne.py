#!/usr/bin/python

##############################################################################
#                                                                            #
#                           By Alessandro ZANNI                              #
#                                                                            #
##############################################################################

# Disclaimer: Do Not Use this program for illegal purposes ;)

import argparse
import time, sys, os
import logging

# browsers
from softwares.browsers.mozilla import Mozilla
from softwares.browsers.chrome import Chrome
from softwares.browsers.opera import Opera
from softwares.browsers.ie import IE
# windows
from softwares.windows.network import Network
from softwares.windows.dot_net import Dot_net
# adminsys
from softwares.adminsys.filezilla import Filezilla
from softwares.adminsys.cyberduck import Cyberduck
from softwares.adminsys.puttycm import Puttycm
from softwares.adminsys.winscp import WinSCP
from softwares.adminsys.coreftp import CoreFTP
from softwares.adminsys.ftpnavigator import FtpNavigator
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
# configuration
from config.header import Header
from config.write_output import write_header, write_footer, print_footer
from config.constant import *

# print the title
Header().first_title()

# Add all modules
modules = {}
# windows
modules['windows'] = {}
modules['windows']['dotnet'] = Dot_net()
modules['windows']['network'] = Network()
# Wifi
modules['wifi'] = {}
modules['wifi']['wifi'] = Wifi()
modules['wifi']['wifipass'] = WifiPass()
# SVN
modules['svn'] = {}
modules['svn']['tortoise'] = Tortoise()
# SQL clients
modules['database'] = {}
modules['database']['sqldeveloper'] = SQLDeveloper()
modules['database']['squirrel'] = Squirrel()
modules['database']['dbvis'] = Dbvisualizer()
# SCP/SSH/FTP/FTPS clients
modules['adminsys'] = {}
modules['adminsys']['filezilla'] = Filezilla()
modules['adminsys']['cyberduck'] = Cyberduck()
modules['adminsys']['puttycm'] = Puttycm()
modules['adminsys']['winscp'] = WinSCP()
modules['adminsys']['coreftp'] = CoreFTP()
modules['adminsys']['ftpnavigator'] = FtpNavigator()
# Mails
modules['mails'] = {}
modules['mails']['outlook'] = Outlook()
modules['mails']['thunderbird'] = Mozilla()
# Chats
modules['chats'] = {}
modules['chats']['skype'] = Skype()
modules['chats']['pidgin'] = Pidgin()
modules['chats']['jitsi'] = Jitsi()
# Browsers
modules['browsers'] = {}
modules['browsers']['firefox'] = Mozilla()
modules['browsers']['ie'] = IE()
modules['browsers']['chrome'] = Chrome()
modules['browsers']['opera'] = Opera()

def output():
	if args['write'] == True:
		constant.output = 'txt'
		if not os.path.exists(constant.folder_name):
			os.makedirs(constant.folder_name)
			write_header()
	del args['write']
	
def verbosity():
	# write on the console + debug file
	if args['verbose']==0: level=logging.INFO
	elif args['verbose'] >= 1: level=logging.DEBUG
	elif args['verbose']>=2: level=logging.WARNING
	
	FORMAT = "%(message)s"
	formatter = logging.Formatter(fmt=FORMAT)
	stream = logging.StreamHandler()
	stream.setFormatter(formatter)
	root = logging.getLogger()
	root.setLevel(level)
	root.addHandler(stream)
	
	del args['verbose']

def launch_module(b):
	ok = False
	# launch only a specific module
	for i in args.keys():
		if args[i]:
			if i in b.keys():
				b[i].retrieve_password()
				ok = True
	
	# launch all modules
	if not ok:
		for i in b.keys():
			b[i].retrieve_password()
		
# Credential Manager
def runWindowsModule():
	launch_module(modules['windows'])

# Wifi
def runWifiModule():
	launch_module(modules['wifi'])

# SVN
def runSVNModule():
	launch_module(modules['svn'])

# SQL clients
def runDatabaseModule():
	launch_module(modules['database'])

# SCP/SSH/FTP/FTPS clients
def runAdminsysModule():
	launch_module(modules['adminsys'])
	
# Mails
def runMailsModule():
	isInteractive = args['isInteractive']
	
	# Advanced Thunderbird master password options
	constant.manually = args['manually']
	constant.path = args['path']
	constant.bruteforce = args['bruteforce']
	constant.defaultpass = args['defaultpass']
	constant.specific_path = args['specific_path']
	constant.mozilla_software = 'Thunderbird'
	
	launch_module(modules['mails'])
	
# Chats
def runChatsModule():
	# manage master password for jitsi
	constant.jitsi_masterpass = args['master_pwd']
	launch_module(modules['chats'])
	
# Web Browsers
def runBrowsersModule():
	isInteractive = args['isInteractive']
	
	# Advanced Firefox master password options
	constant.manually = args['manually']
	constant.path = args['path']
	constant.bruteforce = args['bruteforce']
	constant.defaultpass = args['defaultpass']
	constant.specific_path = args['specific_path']
	constant.mozilla_software = 'Firefox'
	
	# Advanced ie options
	constant.ie_historic = args['historic']
	
	launch_module(modules['browsers'])
	
# ALL
def runAllModules():
	time_to_sleep = 0
	
	runWindowsModule()
	time.sleep(time_to_sleep)
	runWifiModule()
	time.sleep(time_to_sleep)
	runSVNModule()
	time.sleep(time_to_sleep)
	runDatabaseModule()
	time.sleep(time_to_sleep)
	runAdminsysModule()
	time.sleep(time_to_sleep)
	runMailsModule()
	time.sleep(time_to_sleep)
	runChatsModule()
	time.sleep(time_to_sleep)
	runBrowsersModule()

# prompt help if an error occurs
class MyParser(argparse.ArgumentParser):
	def error(self, message):
		sys.stderr.write('error: %s\n\n' % message)
		self.print_help()
		sys.exit(2)

parser = MyParser()

# ------------------------------------------- Advanced options -------------------------------------------
#1- Parent parsers
#1.0- Parent parser: optional
PPoptional = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PPoptional._optionals.title = 'optional arguments'
PPoptional.add_argument('-v', dest='verbose', action='count', default=0, help='write a debug file')
PPoptional.add_argument('--version', action='version', version='Version ' + str(constant.CURRENT_VERSION))

#1.0.1- Parent parser: output
PWrite = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PWrite._optionals.title = 'output'
PWrite.add_argument('-w', dest='write',  action= 'store_true', help = 'write a text file on the current directory')

#1.0.2- Parent parser: Advanced Mozilla master password options
PMasterPass_Firefox = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PMasterPass_Firefox._optionals.title = 'Advanced Mozilla master password options'
PMasterPass_Firefox.add_argument('-m', action='store', dest='manually', help='enter the master password manually')
PMasterPass_Firefox.add_argument('-p', action='store', dest='path', help='path of a dictionnary file')
PMasterPass_Firefox.add_argument('-b', type=int, action='store', dest='bruteforce', help='number of caracter to brute force')
PMasterPass_Firefox.add_argument('-d', action='store_true', dest='defaultpass', help='try 500 most common passwords')
PMasterPass_Firefox.add_argument('-s', action='store', dest='specific_path', help='enter the specific path to a profile you want to crack')

#1.0.2- Parent parser: Advanced ie option
PEntropy_Ie = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PEntropy_Ie._optionals.title = 'Advanced ie option'
PEntropy_Ie.add_argument('-l', action='store', dest='historic', help='text file with a list of websites')

#1.0.3- Parent parser: Advanced jitsi option
PMasterPass_Jitsi = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PMasterPass_Jitsi._optionals.title = 'Advanced jitsi option'
PMasterPass_Jitsi.add_argument('-ma', action='store', dest='master_pwd', help='enter the master password manually')

#1.0.4- Parent parser: Interactive mode option
PMode = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PMode._optionals.title = 'Interactive mode'
PMode.add_argument('-i', dest='isInteractive', action='store_true', help='launch the program in an interactive mode')


# ------------------------------------------- Functions (by Modules) -------------------------------------------
#1.1- Parent parser: browsers
PBrowsers = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PBrowsers._optionals.title = 'Web browsers supported'
PBrowsers.add_argument('-f', action='store_true', dest='firefox', help='firefox')
PBrowsers.add_argument('-e', action='store_true', dest='ie', help='internet explorer from version 7 to 11 (but not with win8)')
PBrowsers.add_argument('-c', action='store_true', dest='chrome', help='chrome')
PBrowsers.add_argument('-o', action='store_true', dest='opera', help='opera')

#1.1- Parent parser: chats
PChats = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PChats._optionals.title = 'Chat clients supported'
PChats.add_argument('-s', action='store_true', dest='skype', help='skype')
PChats.add_argument('-p', action='store_true', dest='pidgin', help='pidgin')
PChats.add_argument('-j', action='store_true', dest='jitsi', help='jitsi')

#1.2- Parent parser: mails
PMails = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PMails._optionals.title = 'Email clients supported'
PMails.add_argument('-o', action='store_true', dest='outlook', help='outlook - IMAP, POP3, HTTP, SMTP, LDPAP (not Exchange)')
PMails.add_argument('-t', action='store_true', dest='thunderbird', help='thunderbird')

#1.3- Parent parser: adminsys
PAdminsys = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PAdminsys._optionals.title = 'SCP/SSH/FTP/FTPS clients supported'
PAdminsys.add_argument('-f', action='store_true', dest='filezilla', help='filezilla')
PAdminsys.add_argument('-c', action='store_true', dest='cyberduck', help='cyberduck')
PAdminsys.add_argument('-p', action='store_true', dest='puttycm', help='puttycm')
PAdminsys.add_argument('-scp', action='store_true', dest='winscp', help='winscp')
PAdminsys.add_argument('-core', action='store_true', dest='coreftp', help='coreftp')
PAdminsys.add_argument('-ftp', action='store_true', dest='ftpnavigator', help='FTP Navigator')

#1.4- Parent parser: database
PDatabase = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PDatabase._optionals.title = 'SQL clients supported'
PDatabase.add_argument('-s', action='store_true', dest='sqldeveloper', help='sqldeveloper')
PDatabase.add_argument('-q', action='store_true', dest='squirrel', help='squirrel')
PDatabase.add_argument('-d', action='store_true', dest='dbvis', help='dbvisualizer')

#1.5- Parent parser: svn
PSVN = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PSVN._optionals.title = 'SVN clients supported'
PSVN.add_argument('-t', action='store_true', dest='tortoise', help='tortoise')

#1.6- Parent parser: wifi
PWifi = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PWifi._optionals.title = 'Wifi'
PWifi.add_argument('-wi', action='store_true', dest='wifi', help='Vista and higher - Need Admin Privileges (UAC Bypassed)')
# Manage wifi (when executed with a system account)
PWifi.add_argument('--HiddenWifiArgs', action='store_true', dest='wifipass', help=argparse.SUPPRESS)

#1.6- Parent parser: windows
PWindows = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PWindows._optionals.title = 'Windows credentials (credential manager, etc.)'
PWindows.add_argument('-d', action='store_true', dest='dotnet', help='domain visible network (.Net Passport) Passwords')
PWindows.add_argument('-n', action='store_true', dest='network', help='generic network credentials')

# ------------------------------------------- Main Modules -------------------------------------------
#2- main commands
subparsers = parser.add_subparsers(help='Choose a main command')

#2.a- Run all modules
parser_all = subparsers.add_parser('all',parents=[PPoptional, PMode, PMasterPass_Firefox, PEntropy_Ie, PMasterPass_Jitsi, PWrite],help='Run all modules')
parser_all.set_defaults(func=runAllModules,auditType='all')

#2.b- Run browsers module
parser_browsers = subparsers.add_parser('browsers',parents=[PPoptional, PBrowsers, PMode, PMasterPass_Firefox, PEntropy_Ie, PWrite],help='Run browsers module')
parser_browsers.set_defaults(func=runBrowsersModule,auditType='browsers')

#2.c- Run chats module
parser_chats = subparsers.add_parser('chats',parents=[PPoptional, PChats, PMasterPass_Jitsi, PWrite],help='Run chats module')
parser_chats.set_defaults(func=runChatsModule,auditType='chats')

#2.d- Run mails module
parser_mails = subparsers.add_parser('mails',parents=[PPoptional, PMails, PMode, PMasterPass_Firefox, PWrite],help='Run mails module')
parser_mails.set_defaults(func=runMailsModule,auditType='mails')

#2.e- Run adminsys module
parser_adminsys = subparsers.add_parser('adminsys',parents=[PPoptional, PAdminsys, PWrite],help='Run adminsys module')
parser_adminsys.set_defaults(func=runAdminsysModule,auditType='adminsys')

#2.f- Run database module
parser_database = subparsers.add_parser('database',parents=[PPoptional, PDatabase, PWrite],help='Run database module')
parser_database.set_defaults(func=runDatabaseModule,auditType='database')

#2.g- Run svn module
parser_svn = subparsers.add_parser('svn',parents=[PPoptional, PSVN, PWrite],help='Run svn module')
parser_svn.set_defaults(func=runSVNModule,auditType='svn')

#2.h- Run wifi module
parser_wifi = subparsers.add_parser('wifi',parents=[PPoptional, PWifi, PWrite],help='Run wifi module')
parser_wifi.set_defaults(func=runWifiModule,auditType='wifi')

#2.i- Run windows module
parser_windows = subparsers.add_parser('windows',parents=[PPoptional, PWindows, PWrite],help='Run windows module')
parser_windows.set_defaults(func=runWindowsModule,auditType='windows')

# ------------------------------------------- Parse arguments -------------------------------------------
args = dict(parser.parse_args()._get_kwargs())
arguments = parser.parse_args()
start_time = time.time()
output()
verbosity()
arguments.func()

# print the number of passwords found
if constant.output == 'txt':
	write_footer()
print_footer()

elapsed_time = time.time() - start_time
print 'elapsed time = ' + str(elapsed_time)
