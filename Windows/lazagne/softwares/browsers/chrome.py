from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import sqlite3
import shutil
import json
import os

class Chrome(ModuleInfo):
	def __init__(self):
		options = {'command': '-c', 'action': 'store_true', 'dest': 'chrome', 'help': 'chrome'}
		ModuleInfo.__init__(self, 'chrome', 'browsers', options)

	# main function
	def run(self, software_name = None):		
		homedrive = constant.profile['HOMEDRIVE']
		homepath = constant.profile['HOMEPATH']
		
		# all possible path
		pathTab = [
			homedrive + homepath + '\\Local Settings\\Application Data\\Google\\Chrome\\User Data', 
			homedrive + homepath + '\\AppData\\Local\\Google\\Chrome\\User Data', 
		]

		application_path = [p for p in pathTab if os.path.exists(p)]
		if not application_path:
			print_debug('INFO', 'Google Chrome not installed.')
			return

		# keep the first existing path
		application_path = application_path[0]

		# try to list all users profile
		profiles = []
		if os.path.exists(os.path.join(application_path, 'Local State')):
			with open(os.path.join(application_path, 'Local State')) as file: 
				try:
					data = json.load(file)
					for profile in data['profile']['info_cache']:
						profiles.append(profile)
				except:
					pass

		if not profiles:
			profiles.append('Default')

		pwdFound = []
		for profile in profiles:
			database_path = os.path.join(application_path, profile, 'Login Data')
			if not os.path.exists(database_path):
				print_debug('INFO', 'User database not found')
				continue

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
				continue 
			
			# Get the results
			try:
				cursor.execute('SELECT action_url, username_value, password_value FROM logins')
			except:
				print_debug('ERROR', 'Google Chrome seems to be used, the database is locked. Kill the process and try again !')
				continue
			
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
