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
import json
import getpass
import traceback
from lazagne.softwares.browsers.mozilla import Mozilla

# Configuration
from lazagne.config.header import Header
from lazagne.config.write_output import write_header, write_footer, print_footer, parseJsonResultToBuffer, print_debug, print_output
from lazagne.config.constant import *
from lazagne.config.manageModules import get_categories, get_modules

category = get_categories()
moduleNames = get_modules()

# Tab containing all passwords
stdoutRes = []

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

# write output to file (json and txt files)
def write_in_file(result):
	try:
		if constant.output == 'json' or constant.output == 'all':
			# Human readable Json format 
			prettyJson = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
			with open(constant.folder_name + os.sep + constant.file_name_results + '.json', 'w+') as f:
				f.write(prettyJson.encode('utf-8', errors='replace'))
			print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.json'

		if constant.output == 'txt' or constant.output == 'all':
			with open(constant.folder_name + os.sep + constant.file_name_results + '.txt', 'a+b') as f:
				f.write(parseJsonResultToBuffer(result))
			write_footer()
			print '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.txt'

	except Exception as e:
		print_debug('ERROR', 'Error writing the output file: %s' % e)

def launch_module(module):
	ok = False
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
		modulesToLaunch = module

	for i in modulesToLaunch:
		try:
			Header().title_info(i.capitalize()) 		# print title
			pwdFound = module[i].run(i.capitalize())	# run the module
			print_output(i.capitalize(), pwdFound) 		# print the results

			# return value - not used but needed 
			yield True, i.capitalize(), pwdFound
		except:
			traceback.print_exc()
			print
			error_message = traceback.format_exc()
			yield False, i.capitalize(), error_message

# Run module
def runModule(category_choosed, need_high_privileges=False, need_system_privileges=False, not_need_to_be_in_env=False, cannot_be_impersonate_using_tokens=False):
	global category

	if category_choosed != 'all':
		category = [category_choosed]

	for categoryName in category:
		for r in launch_module(modules[categoryName]):
			yield r

# Prompt help if an error occurs
class MyParser(argparse.ArgumentParser):
	def error(self, message):
		sys.stderr.write('error: %s\n\n' % message)
		self.print_help()
		sys.exit(2)

def runLaZagne(category_choosed='all'):
	user = getpass.getuser()
	constant.finalResults = {}
	constant.finalResults['User'] = user
	
	print '\n\n########## User: %s ##########\n' % user.encode('utf-8', errors='ignore')
	yield 'User', user

	for r in runModule(category_choosed):
		yield r

	stdoutRes.append(constant.finalResults)

if __name__ == '__main__':

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
		for module in modules[c]:
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
		subparsers.add_parser(d,parents=dic[d]['parents'],help=dic[d]['help']).set_defaults(func=dic[d]['func'],auditType=d)

	# ------------------------------------------- Parse arguments -------------------------------------------
	args = dict(parser.parse_args()._get_kwargs())
	arguments = parser.parse_args()
	category_choosed = args['auditType']
	
	# Define constant variables
	output()
	verbosity()
	manage_advanced_options()

	start_time = time.time()

	for r in runLaZagne():
		pass

	# if constant.output == 'json' or constant.output == 'all':
	# 	# Human readable Json format 
	# 	prettyJson = json.dumps(constant.finalResults, sort_keys=True, indent=4, separators=(',', ': '))
	# 	with open(constant.folder_name + os.sep + constant.file_name_results + '.json', 'w+') as f:
	# 		json.dump(prettyJson, f)

	# # Print the number of passwords found
	# if constant.output == 'txt' or constant.output == 'all':
	# 	with open(constant.folder_name + os.sep + constant.file_name_results + '.txt', 'a+b') as f:
	# 		f.write(parseJsonResultToBuffer(constant.finalResults).encode('utf-8'))
	# 	write_footer()

	write_in_file(stdoutRes)
	print_footer()

	elapsed_time = time.time() - start_time
	print '\nelapsed time = ' + str(elapsed_time)
