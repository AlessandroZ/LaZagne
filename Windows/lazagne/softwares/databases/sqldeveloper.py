from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
from Crypto.Cipher import DES
import binascii
import base64
import hashlib
import array
import re
import os

class SQLDeveloper(ModuleInfo):
	def __init__(self):
		options = {'command': '-s', 'action': 'store_true', 'dest': 'sqldeveloper', 'help': 'sqldeveloper'}
		ModuleInfo.__init__(self, 'sqldeveloper', 'database', options, need_to_be_in_env=False)
		
		self._salt = self.get_salt()
		self._passphrase = None
		self._iteration = 42

	def get_salt(self):
		salt_array = [5, 19, -103, 66, -109, 114, -24, -83]
		salt = array.array('b', salt_array)
		hexsalt = binascii.hexlify(salt)
		return binascii.unhexlify(hexsalt)
	
	def get_iteration(self):
		return 42
	
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
	
	def get_application_path(self):
		directory = os.path.join(constant.profile['APPDATA'], 'SQL Developer')
		if os.path.exists(directory):
			for d in os.listdir(directory):
				if d.startswith('system'):
					directory += os.sep + d
					return directory
			return 'SQL_NO_PASSWD'
		else:
			return False
		
	
	def get_passphrase(self, path):
		for p in os.listdir(path):
			if p.startswith('o.sqldeveloper.12'):
				path += os.sep + p
				break
		
		xml_file = path + os.sep + 'product-preferences.xml'
		if os.path.exists(xml_file):
			tree = ET.ElementTree(file=xml_file)
			for elem in tree.iter():
				if 'n' in elem.attrib.keys():
					if elem.attrib['n'] == 'db.system.id':
						return elem.attrib['v']
			return 'Not_Found'
		else:
			return 'xml_Not_Found'

	def get_infos(self, path):
		for p in os.listdir(path):
			if p.startswith('o.jdeveloper.db.connection'):
				path += os.sep + p
				break
		
		xml_file = os.path.join(path, 'connections.xml')
		if os.path.exists(xml_file):
			tree = ET.ElementTree(file=xml_file)
			pwdFound = []
			values = {}
			for elem in tree.iter():
				if 'addrType' in elem.attrib.keys():
					if elem.attrib['addrType'] == 'sid':
						for e in elem.getchildren():
							values['SID'] = e.text
					
					elif elem.attrib['addrType'] == 'port':
						for e in elem.getchildren():
							values['Port'] = e.text
							
					elif elem.attrib['addrType'] == 'user':
						for e in elem.getchildren():
							values['Login'] = e.text
					
					elif elem.attrib['addrType'] == 'ConnName':
						for e in elem.getchildren():
							values['Name'] = e.text
					
					elif elem.attrib['addrType'] == 'customUrl':
						for e in elem.getchildren():
							values['URL'] = e.text
							
					elif elem.attrib['addrType'] == 'SavePassword':
						for e in elem.getchildren():
							values['SavePassword'] = e.text
				
					elif elem.attrib['addrType'] == 'hostname':
						for e in elem.getchildren():
							values['Host'] = e.text
							
					elif elem.attrib['addrType'] == 'password':
						for e in elem.getchildren():
							pwd = self.decrypt(e.text)
							values['Password'] = pwd
							
					elif elem.attrib['addrType'] == 'driver':
						for e in elem.getchildren():
							values['Driver'] = e.text
							
							# password found 
							pwdFound.append(values)
							
			return pwdFound
		else:
			print_debug('ERROR', 'The xml file connections.xml containing the passwords has not been found.')
	
	def run(self, software_name = None):

		application_path = self.get_application_path()	
		if not application_path:
			print_debug('INFO','SQL Developer not installed.')
		
		elif application_path == 'SQL_NO_PASSWD':
			print_debug('INFO', 'No passwords found.')
			
		else:
			self._passphrase = self.get_passphrase(application_path)
			if self._passphrase == 'Not_Found':
				print_debug('WARNING', 'The self._passphrase used to encrypt has not been found.')
			
			elif self._passphrase == 'xml_Not_Found':
				print_debug('WARNING', 'The xml file containing the self._passphrase has not been found.')
				
			else:
				return self.get_infos(application_path)
