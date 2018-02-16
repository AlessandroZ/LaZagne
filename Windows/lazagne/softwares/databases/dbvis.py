# -*- coding: utf-8 -*- 
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
		ModuleInfo.__init__(self, name='dbvis', category='databases')

		self._salt 			= self.get_salt()
		self._passphrase 	= 'qinda'
		self._iteration 	= 10

	def get_salt(self):
		salt_array 	= [-114,18,57,-100,7,114,111,90]
		salt 		= array.array('b', salt_array)
		hexsalt 	= binascii.hexlify(salt)
		return binascii.unhexlify(hexsalt)

	def get_derived_key(self, password, salt, count):
		key = bytearray(password) + salt

		for i in range(count):
			m 	= hashlib.md5(key)
			key = m.digest()
		return (key[:8], key[8:])

	def decrypt(self, msg):
		enc_text 	= base64.b64decode(msg)
		(dk, iv) 	= self.get_derived_key(self._passphrase, self._salt, self._iteration)
		crypter 	= DES.new(dk, DES.MODE_CBC, iv)
		text 		= crypter.decrypt(enc_text)
		return re.sub(r'[\x01-\x08]','',text)

	def run(self, software_name=None):	
		path = os.path.join(constant.profile['HOMEPATH'], u'.dbvis', u'config70', u'dbvis.xml')
		if os.path.exists(path):
			tree = ET.ElementTree(file=path)
		
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
					ciphered_password 	= e.find('Password').text
					password 			= self.decrypt(ciphered_password)
					values['Password'] 	= password
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

