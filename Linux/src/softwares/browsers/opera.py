import sys, struct, hashlib, binascii, re, os
from Crypto.Cipher import DES3
from ConfigParser import RawConfigParser
import sqlite3
from config.header import Header
from config.constant import *
from config.write_output import print_debug, print_output
from config.moduleInfo import ModuleInfo

CIPHERED_FILE = ''

class Opera(ModuleInfo):
	def __init__(self):
		options = {'command': '-o', 'action': 'store_true', 'dest': 'opera', 'help': 'opera'}
		ModuleInfo.__init__(self, 'opera', 'browsers', options)
	
	def run(self):
		# print the title
		Header().title_info('Opera')
	
		# retrieve opera folder
		path = self.get_path()
		
		if not path:
			print_debug('INFO', 'Opera not installed.')
			return
		
		passwords = ''
		# check the use of master password
		if not os.path.exists(path + os.sep + 'operaprefs.ini'):
			print_debug('INFO', 'The preference file operaprefs.ini has not been found.')
		else:
			if self.masterPasswordUsed(path) == '0':
				print_debug('INFO', 'No master password defined.')
			elif self.masterPasswordUsed(path) == '1':
				print_debug('WARNING', 'A master password is used.')
			else:
				print_debug('WARNING', 'An error occurs, the use of master password is not sure.')
		print
		
		passwords = self.decipher_old_version(path)
		
		if passwords:
			self.parse_results(passwords)
		else:
			print_debug('INFO', 'The wand.dat seems to be empty')

	
	def get_path(self):
		path = os.path.expanduser("~/.opera")
		if os.path.exists(path):
			return path
		else:
			return None
	
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
		
		
	def masterPasswordUsed(self, path):
		# the init file is not well defined so lines have to be removed before to parse it
		cp = RawConfigParser()
		f = open(path + os.sep + 'operaprefs.ini', 'rb')
		
		f.readline() # discard first line
		while 1:
			try:
				cp.readfp(f)
				break
			except:
				f.readline()    # discard first line
		try:
			master_pass = cp.get('Security Prefs','Use Paranoid Mailpassword')
			return master_pass
		except:
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
					values['Username'] = password
				elif tmp_cpt == 4:
					values['Password'] = password
					pwdFound.append(values)
				
			# url
			match=re.search(r'^http', password)
			if match:
				cpt +=1
				if cpt == 1:
					tmp_url = password
				elif cpt == 2:
					values['URL'] = tmp_url
		
		# print the results
		print_output('Opera', pwdFound)


