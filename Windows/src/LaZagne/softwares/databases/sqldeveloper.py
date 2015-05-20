import binascii, base64, array
from Crypto.Cipher import DES
import hashlib, re, os
import xml.etree.cElementTree as ET
from config.constant import *
from config.write_output import print_output, print_debug
from config.header import Header
from config.moduleInfo import ModuleInfo

class SQLDeveloper(ModuleInfo):
	def __init__(self):
		options = {'command': '-s', 'action': 'store_true', 'dest': 'sqldeveloper', 'help': 'sqldeveloper'}
		ModuleInfo.__init__(self, 'sqldeveloper', 'database', options)
	
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
	
	def decrypt(self, salt, msg, password):
		enc_text = base64.b64decode(msg)
		(dk, iv) = self.get_derived_key(password, salt, self.get_iteration())
		crypter = DES.new(dk, DES.MODE_CBC, iv)
		text = crypter.decrypt(enc_text)
		return re.sub(r'[\x01-\x08]','',text)
	
	def get_mainPath(self):
		if 'APPDATA' in os.environ:
			directory = os.environ.get('APPDATA') + os.sep + 'SQL Developer'
			if os.path.exists(directory):
				for d in os.listdir(directory):
					if d.startswith('system'):
						directory += os.sep + d
						return directory
				return 'SQL_NO_PASSWD'
			else:
				return 'SQL_NOT_EXISTS'
		else:
			return 'Error'
	
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

	def get_infos(self, path, passphrase, salt):
		for p in os.listdir(path):
			if p.startswith('o.jdeveloper.db.connection'):
				path += os.sep + p
				break
		
		xml_file = path + os.sep + 'connections.xml'
		
		if os.path.exists(xml_file):
			tree = ET.ElementTree(file=xml_file)
			pwdFound = []
			values = {}
			for elem in tree.iter():
				if 'addrType' in elem.attrib.keys():
					if elem.attrib['addrType'] == 'sid':
						for e in elem.getchildren():
							values['sid'] = e.text
					
					elif elem.attrib['addrType'] == 'port':
						for e in elem.getchildren():
							values['port'] = e.text
							
					elif elem.attrib['addrType'] == 'user':
						for e in elem.getchildren():
							values['user'] = e.text
					
					elif elem.attrib['addrType'] == 'ConnName':
						for e in elem.getchildren():
							values['Connection Name'] = e.text
					
					elif elem.attrib['addrType'] == 'customUrl':
						for e in elem.getchildren():
							values['custom Url'] = e.text
							
					elif elem.attrib['addrType'] == 'SavePassword':
						for e in elem.getchildren():
							values['SavePassword'] = e.text
				
					elif elem.attrib['addrType'] == 'hostname':
						for e in elem.getchildren():
							values['hostname'] = e.text
							
					elif elem.attrib['addrType'] == 'password':
						for e in elem.getchildren():
							pwd = self.decrypt(salt, e.text, passphrase)
							values['password'] = pwd
							
					elif elem.attrib['addrType'] == 'driver':
						for e in elem.getchildren():
							values['driver'] = e.text
							
							# password found 
							pwdFound.append(values)
							
			# print the results
			print_output("SQL Developer", pwdFound)
		else:
			print_debug('ERROR', 'The xml file connections.xml containing the passwords has not been found.')
	
	def run(self):
		# print title
		Header().title_info('SQL Developer')
		
		mainPath = self.get_mainPath()
		if mainPath == 'Error':
			print_debug('ERROR', 'The APPDATA environment variable is not defined.')
		
		elif mainPath == 'SQL_NOT_EXISTS':
			print_debug('INFO','SQL Developer not installed.')
		
		elif mainPath == 'SQL_NO_PASSWD':
			print_debug('INFO', 'No passwords found.')
			
		else:
			passphrase = self.get_passphrase(mainPath)
			if passphrase == 'Not_Found':
				print_debug('WARNING', 'The passphrase used to encrypt has not been found.')
			
			elif passphrase == 'xml_Not_Found':
				print_debug('WARNING', 'The xml file containing the passphrase has not been found.')
				
			else:
				salt = self.get_salt()
				self.get_infos(mainPath, passphrase, salt)
