# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.winstructure import *
from lazagne.config.constant import *
import traceback
import tempfile
import sqlite3
import random
import string
import shutil
import json
import os

class Opera(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'opera', 'browsers', dpapi_used=True)
	
	def run(self, software_name=None):	
		pwdFound = []
		paths 	 = [u'{appdata}\\Opera Software\\Opera Stable'.format(appdata=constant.profile['APPDATA'])]

		for path in paths:
			if os.path.exists(path):
				random_dbname 	= ''
				database_path 	= os.path.join(path, u'Login Data')
				if not os.path.exists(database_path):
					print_debug('INFO', u'User database not found')
					continue

				# Copy database before to query it (bypass lock errors)
				try:
					random_dbname = ''.join([random.choice(string.ascii_lowercase) for x in range(0, random.randint(6, 12))])
					shutil.copy(database_path, os.path.join(unicode(tempfile.gettempdir()), random_dbname))
					database_path = os.path.join(unicode(tempfile.gettempdir()), random_dbname)
				except Exception:
					print_debug('DEBUG', traceback.format_exc())

				# Connect to the Database
				try:
					conn 	= sqlite3.connect(database_path)
					cursor  = conn.cursor()
				except Exception,e:
					print_debug('DEBUG', str(e))
					print_debug('ERROR', u'An error occured opening the database file')
					continue 

				# Get the results
				try:
					cursor.execute('SELECT action_url, username_value, password_value FROM logins')
				except:
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
						print_debug('DEBUG', traceback.format_exc())
				
				conn.close()
				if database_path.endswith(random_dbname):
					os.remove(database_path)

		return pwdFound
