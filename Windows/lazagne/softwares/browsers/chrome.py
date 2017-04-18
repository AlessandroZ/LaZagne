from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import sqlite3
import shutil
import os

class Chrome(ModuleInfo):
	def __init__(self):
		options = {'command': '-c', 'action': 'store_true', 'dest': 'chrome', 'help': 'chrome'}
		ModuleInfo.__init__(self, 'chrome', 'browsers', options)

	# main function
	def run(self, software_name = None):		
		homedrive = constant.profile['HOMEDRIVE']
		homepath = constant.profile['HOMEPATH']
		
		# All possible path
		pathTab = [
			homedrive + homepath + '\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\Login Data', 
			homedrive + homepath + '\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data', 
			homedrive + '\\Users\\' + constant.username + '\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\Login Data',
			homedrive + '\\Users\\' + constant.username + '\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data',
			'C:\\Users\\' + constant.username + '\\Local Settings\\Application Data\\Google\\Chrome\\User Data\\Default\\Login Data',
			'C:\\Users\\' + constant.username + '\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data'
		]

		database_path = [p for p in pathTab if os.path.exists(p)]
		if not database_path:
			print_debug('INFO', 'Google Chrome not installed.')
			return
		
		database_path = database_path[0]

		# Copy database before to query it (bypass lock errors)
		try:
			shutil.copy(database_path, os.path.join(os.getcwd(), 'tmp_db'))
			database_path = os.path.join(os.getcwd(), 'tmp_db')
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
			try:
				# Decrypt the Password
				password = Win32CryptUnprotectData(result[2])
				pwdFound.append(
					{
						'URL'		: result[0], 
						'Login'		: result[1], 
						'Password'	: password
					}
				)
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
		
		conn.close()
		if database_path.endswith('tmp_db'):
			os.remove(database_path)

		return pwdFound
		