from Crypto.Hash import MD5
from Crypto.Cipher import DES
import binascii, array, hashlib
import base64, re, os
import xml.etree.cElementTree as ET
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo

class DbVisualizer(ModuleInfo):
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
			values = {}
			for elem in tree.iter('Databases'):
				values = {}
				passwordFound = False

				for e in elem.iter():
					if 'Alias' == e.tag:
						values['Name'] = str(e.text)

					if 'Userid' == e.tag:
						values['Login'] = str(e.text)

					if 'Password' == e.tag:
						ciphered_password = e.text
						try:
							password = self.decrypt(salt, ciphered_password, passphrase)
							values['Password'] = password
							passwordFound = True
						except Exception,e:
							print_debug('ERROR', '{0}'.format(e))

					if 'UrlVariables' == e.tag:
						for el in e.getchildren():
							values['Driver'] = str(el.text).strip()

							for ele in el.getchildren():
								if 'Server' == ele.attrib['UrlVariableName']:
									values['Host'] = str(ele.text)

								if 'Port' == ele.attrib['UrlVariableName']:
									values['Port'] = str(ele.text)

								if 'SID' == ele.attrib['UrlVariableName']:
									values['SID'] = str(ele.text)

						if passwordFound:
							pwdFound.append(values)

			return pwdFound

	def get_mainPath(self):
		directory = '~/.dbvis'
		directory = os.path.expanduser(directory)

		if os.path.exists(directory):
			return directory
		else:
			return 'DBVIS_NOT_EXISTS'

	def run(self, software_name = None):
		mainPath = self.get_mainPath()

		if mainPath == 'DBVIS_NOT_EXISTS':
			print_debug('INFO', 'DbVisualizer not installed.')

		else:
			passphrase = self.get_passphrase()

			salt = self.get_salt()
			return self.get_infos(mainPath, passphrase, salt)
