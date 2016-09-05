import hashlib, os, re
from base64 import b64decode
import binascii, array
from Crypto.Cipher import AES
from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo

# From https://github.com/mitsuhiko/python-pbkdf2
from pbkdf2 import pbkdf2_bin

class Jitsi(ModuleInfo):
	def __init__(self):
		options = {'command': '-j', 'action': 'store_true', 'dest': 'jitsi', 'help': 'jitsi'}
		suboptions = [{'command': '-ma', 'action': 'store', 'dest': 'master_pwd', 'help': 'enter the master password manually', 'title': 'Advanced jitsi option'}]
		ModuleInfo.__init__(self, 'jitsi', 'chats', options, suboptions)
	
		self.keylen = 16
		self.iterations = 1024
		self.padding = '\f'
		self.account_id = ''
		self.master_password_used = False
		self.masterpass = ' '
	
	def get_salt(self):
		salt_array = [12, 10, 15, 14, 11, 14, 14, 15]
		salt = array.array('b', salt_array)
		hexsalt = binascii.hexlify(salt)
		return binascii.unhexlify(hexsalt)
	
	def get_path(self):
		if constant.appdata:
			directory =  '%s\Jitsi\sip-communicator.properties' % constant.appdata
			if os.path.exists(directory):
				return directory
			return 'JITSI_NOT_EXISTS'

		elif 'APPDATA' in os.environ:
			directory = os.environ.get('APPDATA') + os.sep + 'Jitsi' + os.sep + 'sip-communicator.properties'
			if os.path.exists(directory):
				return directory
			else:
				return 'JITSI_NOT_EXISTS'
		else:
			return 'Error'
		
	def get_info(self, file_properties):
		values = {}
		
		f = open(file_properties,'r')
		line = f.readline()
		
		cpt = 0
		pwdFound = []
		while line:
			if 'ACCOUNT_UID' in line:
				m = re.match(r"(.*)ACCOUNT_UID=(.*$)",line)
				if m:
					# password found
					if cpt > 0:
						pwdFound.append(values)
						cpt = 0
					
					values = {}
					values['Account id'] = m.group(2)
					cpt += 1
				
			if 'ENCRYPTED_PASSWORD' in line:
				m = re.match(r"(.*)ENCRYPTED_PASSWORD=(.*$)",line)
				if m:
					values['Password'] = self.decrypt_password(m.group(2))
					cpt += 2
					
			if 'credentialsstorage.MASTER' in line:
				m = re.match(r"(.*)credentialsstorage.MASTER=(.*$)",line)
				if m:
					values['Masterpass used'] = True
					self.master_password_used = True
			
			line = f.readline()
		
		if len(values) != 0:
			pwdFound.append(values)
		
		f.close()
		return pwdFound
		
	def decrypt_password(self, encrypted_pass):
		salt = self.get_salt()
		
		if self.master_password_used and constant.jitsi_masterpass:
			self.masterpass = constant.jitsi_masterpass
		elif self.master_password_used and not constant.jitsi_masterpass:
			return '\n[!] A master password is used, the password cannot be decrypted. Provide a masterpassword using the -ma option'
		
		# --- Decrypting the password ---
		# generate hash
		secret = pbkdf2_bin(bytes(self.masterpass), salt, self.iterations, self.keylen, hashfunc=hashlib.sha1)
		
		# decrypt password
		cipher = AES.new(secret)
		plaintext = cipher.decrypt(b64decode(encrypted_pass)).rstrip(self.padding)
		
		return plaintext.strip()
	
	# main function
	def run(self, software_name = None):		
		file_properties = self.get_path()
		if file_properties == 'Error':
			print_debug('ERROR', 'The APPDATA environment variable is not defined')
		
		elif file_properties == 'JITSI_NOT_EXISTS':
			print_debug('INFO', 'Jitsi not installed.')
		
		else:
			return self.get_info(file_properties)
		
