from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.dico import get_dico
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
from Crypto.Cipher import AES
import _winreg
import hashlib
import binascii
import struct
import os

class Skype(ModuleInfo):
	def __init__(self):
		options = {'command': '-s', 'action': 'store_true', 'dest': 'skype', 'help': 'skype'}
		ModuleInfo.__init__(self, 'skype', 'chats', options)

	def aes_encrypt(self, message, passphrase):
		IV = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		aes = AES.new(passphrase, AES.MODE_CBC, IV)
		return aes.encrypt(message)

	# get value used to build the salt
	def get_regkey(self):
		try:
			keyPath = 'Software\\Skype\\ProtectedStorage'
			try:
				hkey = _winreg.OpenKey(HKEY_CURRENT_USER, keyPath)
			except Exception, e:
				print_debug('DEBUG', '{0}'.format(e))
				return False
			
			num = _winreg.QueryInfoKey(hkey)[1]
			k = _winreg.EnumValue(hkey, 0)[1]
			return Win32CryptUnprotectData(k)
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return False
			
	# get hash from lazagne.configuration file
	def get_hash_credential(self, xml_file):
		tree = ET.ElementTree(file=xml_file)
		encrypted_hash = tree.find('Lib/Account/Credentials3')
		if encrypted_hash != None:
			return encrypted_hash.text
		else:
			return False
	
	# decrypt hash to get the md5 to bruteforce
	def get_md5_hash(self, enc_hex, key):
		# convert hash from hex to binary
		enc_binary = binascii.unhexlify(enc_hex)

		# retrieve the salt
		salt =  hashlib.sha1('\x00\x00\x00\x00' + key).digest() + hashlib.sha1('\x00\x00\x00\x01' + key).digest()

		# encrypt value used with the XOR operation
		aes_key = self.aes_encrypt(struct.pack('I', 0) * 4, salt[0:32])[0:16]

		# XOR operation
		decrypted = []
		for d in range(16):
			decrypted.append(struct.unpack('B', enc_binary[d])[0] ^ struct.unpack('B', aes_key[d])[0])

		# cast the result byte
		tmp = ''
		for dec in decrypted:
			tmp = tmp + struct.pack(">I", dec).strip('\x00')

		# byte to hex 
		return binascii.hexlify(tmp)
	
	# used for dictionary attack, if user specify a specific file
	def get_dic_file(self, dictionary_path):
		words = []
		if dictionary_path:
			try:
				dicFile = open (dictionary_path,'r')
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
				print_debug('ERROR', 'Unable to open passwords file: %s' % str(dictionary_path))
				return []
			
			for word in dicFile.readlines():
				words.append(word.strip('\n'))
			dicFile.close()
		return words
	
	def dictionary_attack(self, login, md5):
		wordlist = get_dico()
		
		# if the user specify the file path
		if constant.path:
			wordlist += self.get_dic_file(constant.path)

		for word in wordlist:
			hash = hashlib.md5('%s\nskyper\n%s' % (login, word)).hexdigest()
			if hash == md5:
				return word
		return False
	
	# main function
	def run(self, software_name = None):
		directory = constant.profile['APPDATA'] + '\Skype'
		
		if os.path.exists(directory):
			# retrieve the key used to build the salt
			key = self.get_regkey()
			if not key:
				print_debug('ERROR', 'The salt has not been retrieved')
			else:
				pwdFound = []
				for d in os.listdir(directory):
					if os.path.exists(os.path.join(directory, d, 'config.xml')):
						values = {}
						
						try:
							values['Login'] = d
							
							# get encrypted hash from the config file
							enc_hex = self.get_hash_credential(os.path.join(directory, d, 'config.xml'))
							
							if not enc_hex:
								print_debug('WARNING', 'No credential stored on the config.xml file.')
							else:
								# decrypt the hash to get the md5 to brue force
								values['Hash'] = self.get_md5_hash(enc_hex, key)
								values['shema to bruteforce using md5'] = values['Login'] + '\\nskyper\\n<password>'
								
								# Try a dictionary attack on the hash
								password = self.dictionary_attack(values['Login'], values['Hash'])
								if password:
									values['Password'] = password

								pwdFound.append(values)
						except Exception,e:
							print_debug('DEBUG', '{0}'.format(e))

				return pwdFound
		else:
			print_debug('INFO', 'Skype not installed.')
			