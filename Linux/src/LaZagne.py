# !/usr/bin/python

##############################################################################
#                                                                            #
#                           By Alessandro ZANNI                              #
#                                                                            #
##############################################################################

# Disclaimer: Do Not Use this program for illegal purposes ;)

import argparse
import time, sys, os
import logging
from softwares.browsers.mozilla import Mozilla

# Configuration
from config.header import Header
from config.write_output import write_header, write_footer, print_footer
from config.constant import *
from config.manageModules import get_categories, get_modules

# Print the title
Header().first_title()

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
	if args['write'] == True:
		constant.output = 'txt'
		if not os.path.exists(constant.folder_name):
			os.makedirs(constant.folder_name)
			write_header()
	del args['write']

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
	# Launch only a specific module
	for i in args:
		if args[i] and i in b:
			b[i].run()
			ok = True
	
	# Launch all modules
	if not ok:
		for i in b:
			b[i].run()

def manage_advanced_options():

	# file used for dictionary attacks
	if 'path' in args:
		constant.path = args['path']
	if 'bruteforce' in args: 
		constant.bruteforce = args['bruteforce']

	# mozilla advanced options
	if 'manually' in args:
		constant.manually = args['manually']
	if 'specific_path' in args:
		constant.specific_path = args['specific_path']
	
	if 'mails' in args['auditType']:
		constant.mozilla_software = 'Thunderbird'
	elif 'browsers' in args['auditType']:
		constant.mozilla_software = 'Firefox'
	
	# jitsi advanced options
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

# Prompt help if an error occurs
class MyParser(argparse.ArgumentParser):
	def error(self, message):
		sys.stderr.write('error: %s\n\n' % message)
		self.print_help()
		sys.exit(2)

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
PWrite._optionals.title = 'output'
PWrite.add_argument('-w', dest='write',  action= 'store_true', help = 'write a text file on the current directory')

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
dic = {'all':{'parents':parents, 'help':'Run all modules', 'func': runAllModules}}
for c in category:
	parser_tab = [PPoptional, category[c]['parser']]
	if 'subparser' in category[c]:
		if category[c]['subparser']:
			parser_tab += category[c]['subparser']
	parser_tab += [PWrite]
	dic_tmp = {c: {'parents': parser_tab, 'help':'Run %s module' % c, 'func': runModule}}
	dic = dict(dic.items() + dic_tmp.items())

# 2- main commands
subparsers = parser.add_subparsers(help='Choose a main command')
for d in dic:
	subparsers.add_parser(d,parents=dic[d]['parents'],help=dic[d]['help']).set_defaults(func=dic[d]['func'],auditType=d)

# ------------------------------------------- Parse arguments -------------------------------------------
args = dict(parser.parse_args()._get_kwargs())
arguments = parser.parse_args()
start_time = time.time()
output()
verbosity()
arguments.func()

# Print the number of passwords found
if constant.output == 'txt':
	write_footer()
print_footer()

elapsed_time = time.time() - start_time
print 'elapsed time = ' + str(elapsed_time)
