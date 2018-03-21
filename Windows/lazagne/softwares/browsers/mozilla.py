#!/usr/bin/env python
# -*- coding: utf-8 -*- 
# portable decryption functions and BSD DB parsing by Laurent Clevy (@lorenzo2472) from https://github.com/lclevy/firepwd/blob/master/firepwd.py 

from ConfigParser import RawConfigParser
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.dico import get_dico
from lazagne.config.constant import *
from binascii import unhexlify
# https://pypi.python.org/pypi/pyasn1/
from pyasn1.codec.der import decoder
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import DES3
from base64 import b64decode
from struct import unpack
from hashlib import sha1
from ctypes import *
import sqlite3
import json
import hmac 
import os

class Mozilla(ModuleInfo):

	def __init__(self, isThunderbird=False):
		name = 'thunderbird' if isThunderbird else 'firefox'
		
		ModuleInfo.__init__(self, name=name, category='browsers')

	def get_path(self, software_name):
		path = ''
		if software_name == 'Firefox':
			path =  u'{appdata}\\Mozilla\\Firefox'.format(appdata=constant.profile['APPDATA'])
		elif software_name == 'Thunderbird':
			path = u'{appdata}\\Thunderbird'.format(appdata=constant.profile['APPDATA'])
		return path

	def get_firefox_profiles(self, directory):
		""" 
		List all profiles 
		"""
		cp = RawConfigParser()
		try:
			cp.read(os.path.join(directory, 'profiles.ini'))
			profile_list = []
			for section in cp.sections():
				if section.startswith('Profile'):
					if cp.has_option(section, 'Path'):
						profile_list.append(os.path.join(directory, cp.get(section, 'Path').strip()))
			return profile_list
		except:
			return []
	
	def get_key(self, profile, master_password=''):
		"""
		Get main key used to encrypt all data (user / password). 
		Depending on the Firefox version, could be stored in key3.db or key4.db file.
		"""
		key  = None
		try:
			conn = sqlite3.connect(os.path.join(profile, 'key4.db')) # Firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
			c 	 = conn.cursor()
			
			# First check password
			c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
			row = c.next()

			(globalSalt, master_password, entrySalt) = self.manage_masterpassword(master_password='', key_data=row)
			if globalSalt:	
				# Decrypt 3DES key to decrypt "logins.json" content
				c.execute("SELECT a11,a102 FROM nssPrivate;")
				a11, a102 = c.next()
				# a11  : CKA_VALUE
				# a102 : f8000000000000000000000000000001, CKA_ID
				self.printASN1(a11, len(a11), 0)
				"""
				SEQUENCE {
					SEQUENCE {
						OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
						SEQUENCE {
							OCTETSTRING entry_salt_for_3des_key
							INTEGER 01
						}
					}
					OCTETSTRING encrypted_3des_key (with 8 bytes of PKCS#7 padding)
				}
				"""
				decodedA11 	= decoder.decode( a11 ) 
				entrySalt 	= decodedA11[0][0][1][0].asOctets()
				cipherT 	= decodedA11[0][1].asOctets()
				key 		= self.decrypt3DES(globalSalt, master_password, entrySalt, cipherT)
				if key:
					yield key[:24]
				
		except:
			pass
		
		try:
			key_data = self.readBsddb(os.path.join(profile, 'key3.db'))
			
			# Check masterpassword 
			(globalSalt, master_password, entrySalt) = self.manage_masterpassword(master_password='', key_data=key_data, new_version=False)
			if  globalSalt:
				key = self.extractSecretKey(key_data=key_data, globalSalt=globalSalt, master_password=master_password, entrySalt=entrySalt)
				if key:
					yield key[:24]
		except:
			pass
		

	def getShortLE(self, d, a):
		return unpack('<H',(d)[a:a+2])[0]

	def getLongBE(self, d, a):
		return unpack('>L',(d)[a:a+4])[0]

	def printASN1(self, d, l, rl):
		"""
		Used for debug
		"""
		type 	= ord(d[0])
		length 	= ord(d[1])
		if length&0x80 > 0: # http://luca.ntop.org/Teaching/Appunti/asn1.html,
			nByteLength = length&0x7f
			length = ord(d[2])  
			# Long form. Two to 127 octets. Bit 8 of first octet has value "1" and bits 7-1 give the number of additional length octets. 
			skip=1
		else:
			skip=0    

		if type==0x30:
			seqLen = length
			readLen = 0
			while seqLen>0:
				len2 = self.printASN1(d[2+skip+readLen:], seqLen, rl+1)
				seqLen = seqLen - len2
				readLen = readLen + len2
			return length+2
		elif type==6: # OID
			return length+2
		elif type==4: # OCTETSTRING
			return length+2
		elif type==5: # NULL
			# print 0
			return length+2
		elif type==2: # INTEGER
			return length+2
		else:
			if length==l-2:
				self.printASN1( d[2:], length, rl+1)
				return length   
   
	def readBsddb(self, name):   
		""" 
		Extract records from a BSD DB 1.85, hash mode  
		Obsolete with Firefox 58.0.2 and NSS 3.35, as key4.db (SQLite) is used
		"""
		with open(name, 'rb') as f:
			# http://download.oracle.com/berkeley-db/db.1.85.tar.gz
			header 	= f.read(4*15)
			magic 	= self.getLongBE(header,0)
			if magic != 0x61561:
				print_debug('WARNING', u'Bad magic number')
				return False
			
			version = self.getLongBE(header,4)
			if version !=2:
				print_debug('WARNING', u'Bad version !=2 (1.85)')
				return False
			
			pagesize 	= self.getLongBE(header,12)
			nkeys 		= self.getLongBE(header,0x38) 
			readkeys 	= 0
			page 		= 1
			nval 		= 0
			val 		= 1
			db1 		= []

			while (readkeys < nkeys):
				f.seek(pagesize*page)
				offsets 	= f.read((nkeys+1)* 4 +2)
				offsetVals 	= []
				i 			= 0
				nval 		= 0
				val 		= 1
				keys 		= 0

				while nval != val :
					keys 	+=1
					key 	= self.getShortLE(offsets,2+i)
					val 	= self.getShortLE(offsets,4+i)
					nval 	= self.getShortLE(offsets,8+i)
					offsetVals.append(key+ pagesize*page)
					offsetVals.append(val+ pagesize*page)  
					readkeys 	+= 1
					i 			+= 4
				
				offsetVals.append(pagesize*(page+1))
				valKey = sorted(offsetVals)  
				for i in range( keys*2 ):
					f.seek(valKey[i])
					data = f.read(valKey[i+1] - valKey[i])
					db1.append(data)
				page += 1
		
		db = {}
		for i in range( 0, len(db1), 2):
			db[ db1[i+1] ] = db1[ i ]

		return db  

	def decrypt3DES(self, globalSalt, master_password, entrySalt, encryptedData):
		"""
		User master key is also encrypted (if provided, the master_password could be used to encrypt it)
		"""
		# See http://www.drh-consultancy.demon.co.uk/key3.html
		hp 	= sha1(globalSalt + master_password).digest()
		pes = entrySalt + '\x00' * (20 - len(entrySalt))
		chp = sha1(hp + entrySalt).digest()
		k1 	= hmac.new(chp, pes + entrySalt, sha1).digest()
		tk 	= hmac.new(chp, pes, sha1).digest()
		k2 	= hmac.new(chp, tk + entrySalt, sha1).digest()
		k 	= k1 + k2
		iv 	= k[-8:]
		key = k[:24]
		return DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData)

	def extractSecretKey(self, key_data, globalSalt, master_password, entrySalt):

		if unhexlify('f8000000000000000000000000000001') not in key_data:
			return None
		
		privKeyEntry 		= key_data[ unhexlify('f8000000000000000000000000000001') ]
		saltLen 			= ord(privKeyEntry[1])
		nameLen 			= ord(privKeyEntry[2])
		privKeyEntryASN1 	= decoder.decode( privKeyEntry[3 + saltLen + nameLen:] )
		data 				= privKeyEntry[3 + saltLen + nameLen:]
		self.printASN1(data, len(data), 0)
		
		# See https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
		entrySalt 	= privKeyEntryASN1[0][0][1][0].asOctets()
		privKeyData = privKeyEntryASN1[0][1].asOctets()
		privKey 	= self.decrypt3DES(globalSalt, master_password, entrySalt, privKeyData)
		self.printASN1(privKey, len(privKey), 0)
		privKeyASN1 = decoder.decode(privKey)
		prKey 		= privKeyASN1[0][2].asOctets()
		self.printASN1(prKey, len(prKey), 0)
		prKeyASN1 	= decoder.decode(prKey)
		id 			= prKeyASN1[0][1]
		key 		= long_to_bytes(prKeyASN1[0][3])

		print_debug('DEBUG', u'key: {key}'.format(key=repr(key)))
		return key

	def decodeLoginData(self, data):
		asn1data = decoder.decode(b64decode(data)) # First base64 decoding, then ASN1DERdecode
		return asn1data[0][0].asOctets(), asn1data[0][1][1].asOctets(), asn1data[0][2].asOctets() # For login and password, keep :(key_id, iv, ciphertext)

	def getLoginData(self, profile):
		"""
		Get encrypted data (user / password) and host from the json or sqlite files
		"""
		conn 	= sqlite3.connect(os.path.join(profile, 'signons.sqlite'))
		logins 	= []
		c 		= conn.cursor()
		try:
			c.execute("SELECT * FROM moz_logins;")
		except sqlite3.OperationalError: # Since Firefox 32, json is used instead of sqlite3
			loginf 		= open(os.path.join(profile,'logins.json'),'r').read()
			jsonLogins 	= json.loads(loginf)
			if 'logins' not in jsonLogins:
				print_debug('DEBUG', 'No logins key in logins.json')
				return []
			for row in jsonLogins['logins']:
				encUsername = row['encryptedUsername']
				encPassword = row['encryptedPassword']
				logins.append((self.decodeLoginData(encUsername), self.decodeLoginData(encPassword), row['hostname']))
			return logins
		
		# Using sqlite3 database
		for row in c:
			encUsername = row[6]
			encPassword = row[7]
			logins.append((self.decodeLoginData(encUsername), self.decodeLoginData(encPassword), row[1]))
		return logins

	def manage_masterpassword(self, master_password='', key_data=None, new_version=True):
		"""
		Check if a master password is set.
		If so, try to find it using a dictionary attack
		"""
		(globalSalt, master_password, entrySalt) = self.is_master_password_correct(master_password=master_password, key_data=key_data, new_version=new_version)
		
		if not globalSalt:
			print_debug('WARNING', u'Master Password is used !') 
			(globalSalt, master_password, entrySalt) = self.found_master_password(key_data=key_data, new_version=new_version)
			if not master_password:
				return ('', '', '')

		return (globalSalt, master_password, entrySalt)

	def is_master_password_correct(self, key_data, master_password='', new_version=True):
		try:
			if not new_version:
				# See http://www.drh-consultancy.demon.co.uk/key3.html
				pwdCheck 		= key_data['password-check']	
				entrySaltLen 	= ord(pwdCheck[1])
				entrySalt 		= pwdCheck[3: 3 + entrySaltLen]
				encryptedPasswd = pwdCheck[-16:]
				globalSalt 		= key_data['global-salt']
				
			else:
				globalSalt 	= key_data[0] # Item1
				item2 		= key_data[1]
				self.printASN1(item2, len(item2), 0)
				"""
				SEQUENCE {
					SEQUENCE {
						OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
						SEQUENCE {
							OCTETSTRING entry_salt_for_passwd_check
							INTEGER 01
						}
					}
					OCTETSTRING encrypted_password_check
				}
				"""
				decodedItem2 	= decoder.decode(item2) 
				entrySalt 		= decodedItem2[0][0][1][0].asOctets()
				encryptedPasswd	= decodedItem2[0][1].asOctets()
			
			cleartextData 	= self.decrypt3DES(globalSalt, master_password, entrySalt, encryptedPasswd)
			if cleartextData != 'password-check\x02\x02':
				return ('', '', '')

			return (globalSalt, master_password, entrySalt)
		except:
			return ('', '', '')		

	
	def found_master_password(self, key_data, new_version=True):
		"""
		Try to found master_password doing a dictionary attack using the 500 most used passwords
		"""
		wordlist 	= constant.passwordFound + get_dico()
		num_lines 	= (len(wordlist) - 1)
		print_debug('ATTACK', u'%d most used passwords !!! ' % num_lines)

		for word in wordlist:
			globalSalt, master_password, entrySalt = self.is_master_password_correct(key_data=key_data, master_password=word.strip(), new_version=new_version)
			if master_password:	
				print_debug('INFO', u'Master password found: {master_password}'.format(master_password=master_password))
				return globalSalt, master_password, entrySalt
			
		print_debug('WARNING', u'No password has been found using the default list')
		return False
	
	def remove_padding(self, data):
		"""
		Remove PKCS#7 padding
		"""
		try:
			nb = unpack('B', data[-1])[0]
			return data[:-nb]
		except:
			return data

	def decrypt(self, key, iv, ciphertext):
		"""
		Decrypt ciphered data (user / password) using the key previously found
		"""
		data = DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext)
		return self.remove_padding(data)

	def run(self, software_name=None):
		"""
		Main function
		"""
		path = self.get_path(software_name)
		if os.path.exists(path):
			
			pwdFound = []
			for profile in self.get_firefox_profiles(path):
				print_debug('INFO', u'Profile path found: {profile}'.format(profile=profile))

				for key in self.get_key(profile):
					credentials = self.getLoginData(profile)

					for user, passw, url in credentials:
						try:
							pwdFound.append(
								{
									'URL'		: url,
									'Login'		: self.decrypt(key=key, iv=user[1], ciphertext=user[2]),
									'Password'	: self.decrypt(key=key, iv=passw[1], ciphertext=passw[2]),
								}
							)
						except Exception, e:
							print_debug('DEBUG', u'An error occured decrypting the password: {error}'.format(error=e))

					return pwdFound
