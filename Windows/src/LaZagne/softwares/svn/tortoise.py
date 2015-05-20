import sqlite3, win32crypt
import sys, os, platform, base64
from config.write_output import print_output, print_debug
from config.constant import *
from config.header import Header
from config.moduleInfo import ModuleInfo

class Tortoise(ModuleInfo):
	def __init__(self):
		options = {'command': '-t', 'action': 'store_true', 'dest': 'tortoise', 'help': 'tortoise'}
		ModuleInfo.__init__(self, 'tortoise', 'svn', options)

	# main function
	def run(self):
		# print title
		Header().title_info('Tortoise')
		
		file_path = ''
		if 'APPDATA' in os.environ:
			file_path = os.environ.get('APPDATA') + '\\Subversion\\auth\\svn.simple'
		else:
			print_debug('ERROR', 'The APPDATA environment variable is not definded.')
			return
		
		values = {}
		pwdFound = []
		if os.path.exists(file_path):
			for root, dirs, files in os.walk(file_path + os.sep):
				for name_file in files:
					values = {}
					f = open(file_path + os.sep + name_file, 'r')
					
					url = ''
					username = ''
					result = ''
					
					i = 0
					# password
					for line in f:
						if i == -1:
							result = line.replace('\n', '')
							break
						if line.startswith('password'):
							i = -3
						i+=1
					
					i = 0
					# url
					for line in f:
						if i == -1:
							url = line.replace('\n', '')
							break
						if line.startswith('svn:realmstring'):
							i = -3
						i+=1

					i = 0
					# username
					for line in f:
						if i == -1:
							username = line.replace('\n', '')
							break
						if line.startswith('username'):
							i = -3
						i+=1
					
					# unccrypt the password
					if result:
						
						try:
							password = win32crypt.CryptUnprotectData(base64.b64decode(result), None, None, None, 0)[1]
						except:
							password = ''
						
						if password:
							values['URL'] = url
							values['Username'] = username
							values['Password'] = password
							
							pwdFound.append(values)
			# print the results
			print_output("Tortoise", pwdFound)
		else:
			print_debug('INFO', 'Tortoise not installed.')

