import sqlite3
import win32crypt
import sys, os, platform
from config.constant import *
from config.write_output import print_output, print_debug
from config.header import Header
from config.moduleInfo import ModuleInfo

class Chrome(ModuleInfo):
	def __init__(self):
		options = {'command': '-c', 'action': 'store_true', 'dest': 'chrome', 'help': 'chrome'}
		ModuleInfo.__init__(self, 'chrome', 'browsers', options)

	# main function
	def run(self):
		# print title
		Header().title_debug('Chrome')
		
		database_path = ''
		if 'HOMEDRIVE' in os.environ and 'HOMEPATH' in os.environ:
			# For Win7
			path_Win7 = os.environ.get('HOMEDRIVE') + os.environ.get('HOMEPATH') + '\Local Settings\Application Data\Google\Chrome\User Data\Default\Login Data'
			
			# For XP
			path_XP = os.environ.get('HOMEDRIVE') + os.environ.get('HOMEPATH') + '\AppData\Local\Google\Chrome\User Data\Default\Login Data'
			
			if os.path.exists(path_XP):
				database_path = path_XP
			
			elif os.path.exists(path_Win7):
				database_path = path_Win7
			
			else:
				print_debug('INFO', 'Google Chrome not installed.')
				return
		else:
			print_debug('ERROR', 'Environment variables (HOMEDRIVE or HOMEPATH) have not been found')
			return
			
		# Connect to the Database
		conn = sqlite3.connect(database_path)
		cursor = conn.cursor()
		
		# Get the results
		try:
			cursor.execute('SELECT action_url, username_value, password_value FROM logins')
		except:
			print_debug('ERROR', 'Google Chrome seems to be used, the database is locked. Kill the process and try again !')
			return
		
		pwdFound = []
		for result in cursor.fetchall():
			values = {}
			
			# Decrypt the Password
			password = win32crypt.CryptUnprotectData(result[2], None, None, None, 0)[1]
			if password:
				values['Site'] = result[0]
				values['Username'] = result[1]
				values['Password'] = password
				pwdFound.append(values)
		
		# print the results
		print_output("Chrome", pwdFound)
		