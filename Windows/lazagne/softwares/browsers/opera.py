from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
from ConfigParser import RawConfigParser
from Crypto.Cipher import DES3
import binascii
import sqlite3
import struct
import hashlib
import re
import os

class Opera(ModuleInfo):
	def __init__(self):
		options = {'command': '-o', 'action': 'store_true', 'dest': 'opera', 'help': 'opera'}
		ModuleInfo.__init__(self, 'opera', 'browsers', options)

		self.CIPHERED_FILE = ''
	
	def run(self, software_name = None):	
		# retrieve opera folder
		path = self.get_path()
		if not path:
			print_debug('INFO', 'Opera is not installed.')
			return
		
		passwords = ''
		# old versions
		if self.CIPHERED_FILE == 'wand.dat':
			# check the use of master password 
			if not os.path.exists(os.path.join(path, 'operaprefs.ini')):
				print_debug('WARNING', 'The preference file operaprefs.ini has not been found.')
				return
			else:
				
				if self.masterPasswordUsed(path) == '1':
					print_debug('WARNING', 'A master password is used.')
				elif self.masterPasswordUsed(path) != '0':
					print_debug('ERROR', 'An error occurs, the use of master password is not sure.')
			
			passwords = self.decipher_old_version(path)
			if passwords:
				return self.parse_results(passwords)
			else:
				print_debug('INFO', 'The wand.dat seems to be empty')
		# new versions
		else:
			return self.decipher_new_version(path)
	
	def get_path(self):
		# version less than 10
		if os.path.exists(constant.profile['APPDATA'] + '\Opera\Opera\profile'):
			self.CIPHERED_FILE = 'wand.dat'
			return constant.profile['APPDATA'] + '\Opera\Opera\profile'
		
		# version more than 10
		if os.path.exists(constant.profile['APPDATA'] + '\Opera\Opera'):
			self.CIPHERED_FILE = 'wand.dat'
			return constant.profile['APPDATA'] + '\Opera\Opera'
		
		# new versions
		elif os.path.exists(constant.profile['APPDATA'] + '\Opera Software\Opera Stable'):
			self.CIPHERED_FILE = 'Login Data'
			return constant.profile['APPDATA'] + '\Opera Software\Opera Stable'
		
	
	def decipher_old_version(self, path):
		salt = '837DFC0F8EB3E86973AFFF'
		
		# retrieve wand.dat file
		if not os.path.exists(path + os.sep + 'wand.dat'):
			print_debug('WARNING', 'wand.dat file has not been found.')
			return 
		
		# read wand.dat
		f = open(path + os.sep + 'wand.dat', 'rb') 
		file =  f.read()
		fileSize = len(file)
		
		passwords = []
		offset = 0
		while offset < fileSize:

			offset = file.find('\x08', offset) + 1
			if offset == 0:
				break

			tmp_blockLength = offset - 8
			tmp_datalen = offset + 8
			
			blockLength = struct.unpack('!i', file[tmp_blockLength : tmp_blockLength + 4])[0]
			datalen = struct.unpack('!i', file[tmp_datalen : tmp_datalen + 4])[0]
			
			binary_salt = binascii.unhexlify(salt)
			desKey = file[offset: offset + 8]
			tmp = binary_salt + desKey
			
			md5hash1 = hashlib.md5(tmp).digest()
			md5hash2 = hashlib.md5(md5hash1 + tmp).digest() 

			key = md5hash1 + md5hash2[0:8]
			iv = md5hash2[8:]
			
			data = file[offset + 8 + 4: offset + 8 + 4 + datalen]

			des3dec = DES3.new(key, DES3.MODE_CBC, iv)
			try:
				plaintext = des3dec.decrypt(data)
				plaintext = re.sub(r'[^\x20-\x7e]', '', plaintext)
				passwords.append(plaintext)
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
				print_debug('ERROR', 'Failed to decrypt password')
			
			offset += 8 + 4 + datalen
		return passwords
		
	def decipher_new_version(self, path):
		database_path = path + os.sep + 'Login Data'
		if os.path.exists(database_path):
			
			# Connect to the Database
			conn = sqlite3.connect(database_path)
			cursor = conn.cursor()
			
			# Get the results
			try:
				cursor.execute('SELECT action_url, username_value, password_value FROM logins')
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
				print_debug('ERROR', 'Opera seems to be used, the database is locked. Kill the process and try again !')
				return 
			
			pwdFound = []
			for result in cursor.fetchall():
				values = {}
				
				# Decrypt the Password
				password = Win32CryptUnprotectData(result[2])
				if password:
					values['URL'] = result[0]
					values['Login'] = result[1]
					values['Password'] = password
					pwdFound.append(values)

			return pwdFound
		else:
			print_debug('INFO', 'No passwords stored\nThe database Login Data is not present.')
		
	def masterPasswordUsed(self, path):
		
		# the init file is not well defined so lines have to be removed before to parse it
		cp = RawConfigParser()
		f = open(os.path.join(path, 'operaprefs.ini', 'rb'))
		
		f.readline() # discard first line
		while 1:
			try:
				cp.readfp(f)
				break
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
				f.readline() # discard first line
		try:
			master_pass = cp.get('Security Prefs','Use Paranoid Mailpassword')
			return master_pass
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return False
		
	def parse_results(self, passwords):
		
		cpt = 0
		values = {}
		pwdFound = []
		for password in passwords:
			
			# date (begin of the sensitive data)
			match=re.search(r'(\d+-\d+-\d+)', password)
			if match:
				values = {}
				cpt = 0
				tmp_cpt = 0
			
			# after finding 2 urls
			if cpt == 2:
				tmp_cpt += 1
				if tmp_cpt == 2:
					values['Login'] = password
				elif tmp_cpt == 4:
					values['Password'] = password
				
			# url
			match=re.search(r'^http', password)
			if match:
				cpt +=1
				if cpt == 1:
					tmp_url = password
				elif cpt == 2:
					values['URL'] = tmp_url
			pwdFound.append(values)
		
		return pwdFound

