from Crypto.Hash import MD5
from Crypto.Cipher import DES
import binascii, array, hashlib
import base64, re, os
import xml.etree.cElementTree as ET

from config.write_output import print_output, print_debug
from config.constant import *
from config.header import Header
from config.moduleInfo import ModuleInfo

class Dbvisualizer(ModuleInfo):
	def __init__(self):
		options = {'command': '-d', 'action': 'store_true', 'dest': 'dbvis', 'help': 'dbvisualizer'}
		ModuleInfo.__init__(self, 'dbvis', 'database', options)

	# ---- functions used to decrypt the password ----
	def get_salt(self):
		salt_array = [-114,18,57,-100,7,114,111,90]
		salt = array.array('b', salt_array)
		hexsalt = binascii.hexlify(salt)
		return binascii.unhexlify(hexsalt)

	def get_iteration(self):
		return 10

	def get_derived_key(self, password, salt, count):
		key = bytearray(password) + salt

		for i in range(count):
			m = hashlib.md5(key)
			key = m.digest()
		return (key[:8], key[8:])

	def decrypt(self, salt, msg, password):
		enc_text = base64.b64decode(msg)

		(dk, iv) = self.get_derived_key(password, salt, self.get_iteration())
		crypter = DES.new(dk, DES.MODE_CBC, iv)
		text = crypter.decrypt(enc_text)
		return re.sub(r'[\x01-\x08]','',text)

	def get_passphrase(self):
		return 'qinda'

	# ---- end of the functions block ----

	def get_infos(self, path, passphrase, salt):
		xml_file = path + os.sep + 'config70/dbvis.xml'

		if os.path.exists(xml_file):
			tree = ET.ElementTree(file=xml_file)
		
		pwdFound = []
		for e in tree.findall('Databases/Database'):
			values = {}
			try:
				values['Connection Name'] = e.find('Alias').text
			except:
				pass
			
			try:
				values['Userid'] = e.find('Userid').text
			except:
				pass
			
			try:
				ciphered_password = e.find('Password').text
				try:
					password = self.decrypt(salt, ciphered_password, passphrase)
					values['Password'] = password
					passwordFound = True
				except:
					pass
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
							values['Server'] = str(ele.text)
						if 'Port' == ele.attrib['UrlVariableName']:
							values['Port'] = str(ele.text)
						if 'SID' == ele.attrib['UrlVariableName']:
							values['SID'] = str(ele.text)
			except:
				pass
			
			if len(values) > 0:
				pwdFound.append(values)
		
		# print the results
		print_output("DbVisualizer", pwdFound)

	def get_mainPath(self):
		if 'HOMEPATH' in os.environ:
			path = os.environ['HOMEPATH'] + os.sep + '.dbvis'
			if os.path.exists(path):
				return path
			else:
				return 'DBVIS_NOT_EXISTS'
		else:
			return 'var_Env_Not_Found'

	def run(self):
		# print title
		Header().title_info('Dbvisualizer')
		
		mainPath = self.get_mainPath()

		if mainPath == 'DBVIS_NOT_EXISTS':
			print_debug('INFO', 'Dbvisualizer not installed.')
			
		elif mainPath == 'var_Env_Not_Found':
			print_debug('ERROR', 'The HOMEPATH environment variable is not defined.')
			
		else:
			passphrase = self.get_passphrase()

			salt = self.get_salt()
			self.get_infos(mainPath, passphrase, salt)

