#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
	- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
	- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

from collections import defaultdict
from structures import *
from credhist import *
from system import *
import hashlib
import crypto
import os

class MasterKey():
	"""
	This class represents a MasterKey block contained in a MasterKeyFile
	"""
	def __init__(self, mk):
		self.decrypted 		= False
		self.mk 			= mk
		self.key 			= None
		self.key_hash 		= None
	
	def __repr__(self):
		return str(self.mk)

	def decrypt_with_hash(self, sid, pwdhash):
		"""
		Decrypts the masterkey with the given user's hash and SID.
		Simply computes the corresponding key then calls self.decrypt_with_key()
		"""
		self.decrypt_with_key(crypto.derivePwdHash(pwdhash=pwdhash, sid=sid))

	def decrypt_with_password(self, sid, pwd):
		"""
		Decrypts the masterkey with the given user's password and SID.
		Simply computes the corresponding key, then calls self.decrypt_with_hash()
		"""	
		try:
			pwd = pwd.encode("UTF-16LE")
		except:
			return

		for algo in ["sha1", "md4"]:
			self.decrypt_with_hash(sid=sid, pwdhash=hashlib.new(algo, pwd).digest())
			if self.decrypted:
				break

	def decrypt_with_key(self, pwdhash):
		"""
		Decrypts the masterkey with the given encryption key. 
		This function also extracts the HMAC part of the decrypted stuff and compare it with the computed one.
		Note that, once successfully decrypted, the masterkey will not be decrypted anymore; this function will simply return.
		"""
		if self.decrypted or not self.mk.ciphertext:
			return

		# Compute encryption key
		cleartxt 		= crypto.dataDecrypt(self.mk.cipherAlgo, self.mk.hashAlgo, self.mk.ciphertext, pwdhash, self.mk.iv, self.mk.rounds)
		self.key 		= cleartxt[-64:]
		hmacSalt	 	= cleartxt[:16]
		hmac 			= cleartxt[16:16 + self.mk.hashAlgo.digestLength]
		hmacComputed 	= crypto.DPAPIHmac(self.mk.hashAlgo, pwdhash, hmacSalt, self.key)
		self.decrypted 	= hmac == hmacComputed
		if self.decrypted:
			self.key_hash = hashlib.sha1(self.key).digest()

class MasterKeyFile():
	def __init__(self, mkfile):
		self.mkf 		= MKFILE.parse(open(mkfile, 'rb').read())
		self.mk 		= MasterKey(mk=self.mkf.masterkey)
		self.bk 		= MasterKey(mk=self.mkf.backupkey)
		self.decrypted 	= False 

	def __repr__(self):
		return str(self.mkf)

	def get_key(self):
		"""
		Returns the first decrypted block between Masterkey and BackupKey.
		If none has been decrypted, returns the Masterkey block.
		"""
		if self.mk.decrypted:
			return self.mk.key or self.mk.key_hash
		elif self.bk.decrypted:
			return self.bk.key
		return self.mk.key

	def jhash(self, sid=None, context='local'):
		"""
		Compute the hash used to be bruteforced. 
		From the masterkey field of the mk file => mk variable.
		"""
		version 	= -1
		hmac_algo 	= None
		cipher_algo = None
		masterkey 	= self.mk.mk
		
		if 'des3' in str(masterkey.cipherAlgo).lower() and 'hmac' in str(masterkey.hashAlgo).lower():
			version 	= 1
			hmac_algo 	= 'sha1'
			cipher_algo = 'des3'
		
		elif 'aes-256' in str(masterkey.cipherAlgo).lower() and 'sha512' in str(masterkey.hashAlgo).lower():
			version 	= 2
			hmac_algo 	= 'sha512'
			cipher_algo = 'aes256'
		
		else:
			return 'Unsupported combination of cipher {cipher_algo} and hash algorithm {algo} found!'.format(cipher_algo=masterkey.cipherAlgo, algo=masterkey.hashAlgo)
		
		context_int 	= 0
		if context == "domain":
			context_int = 2
		elif context == "local":
			context_int = 1

		return '$DPAPImk${version}*{context}*{sid}*{cipher_algo}*{hmac_algo}*{rounds}*{iv}*{size}*{ciphertext}'.format(
			version 	= version, 
			context 	= context_int, 
			sid 		= sid, 
			cipher_algo = cipher_algo, 
			hmac_algo 	= hmac_algo, 
			rounds 		= masterkey.rounds, 
			iv 			= masterkey.iv.encode("hex"),
			size 		= len(masterkey.ciphertext.encode("hex")), 
			ciphertext 	= masterkey.ciphertext.encode("hex")
		)

class MasterKeyPool():
	"""
	This class is the pivot for using DPAPIck. It manages all the DPAPI structures and contains all the decryption intelligence.
	"""
	def __init__(self):
		self.keys 				= defaultdict(
			lambda: {
				'password' 	: None, 	# contains cleartext password
				'keys'		: [], 		# contains all decrypted mk keys
			}
		)
		self.mkfiles 			= []
		self.credhists 			= {}
		self.mk_dir 			= None
		self.nb_mkf 			= 0
		self.nb_mkf_decrypted 	= 0
		self.preferred_guid 	= None
		self.system 			= None

	def add_master_key(self, mkey):
		"""
		Add a MasterKeyFile is the pool.
		mkey is a string representing the content of the file to add.
		"""
		mkfile = MasterKeyFile(mkey)
		
		# Store all decrypted keys found by guid
		self.keys[mkfile.mkf.guid]['keys'].append(mkfile)

		# Store mkfile object
		self.mkfiles.append(mkfile)

	def load_directory(self, directory):
		"""
		Adds every masterkey contained in the given directory to the pool.
		"""
		if os.path.exists(directory):
			self.mk_dir = directory
			for k in os.listdir(directory):
				try:
					self.add_master_key(os.path.join(directory, k))
					self.nb_mkf += 1
				except:
					pass
			return True
		return False

	def get_master_keys(self, guid):
		"""
		Returns an array of Masterkeys corresponding to the given GUID.
		"""
		return self.keys.get(guid, {}).get('keys')

	def get_password(self, guid):
		"""
		Returns the password found corresponding to the given GUID.
		"""
		return self.keys.get(guid, {}).get('password')

	def add_credhist_file(self, sid, credfile):
		"""
		Adds a Credhist file to the pool.
		"""
		try:
			self.credhists[sid] = CredHistFile(credfile)
		except:
			pass

	def get_preferred_guid(self):
		"""
		Extract from the Preferred file the associated GUID. 
		This guid represent the preferred masterkey used by the system. 
		This means that it has been encrypted using the current password not an older one. 
		"""
		if self.preferred_guid: 
			return self.preferred_guid

		if self.mk_dir:
			preferred_file = os.path.join(self.mk_dir, u'Preferred')
			if os.path.exists(preferred_file):
				with open(preferred_file, 'rb') as pfile:
					self.preferred_guid = GuidAdapter(GUID).parse(pfile.read(16))
				return self.preferred_guid

		return False

	def get_cleartext_password(self, guid=None):
		"""
		Get cleartext password if already found of the associated guid. 
		If not guid specify, return the associated password of the preferred guid.
		"""
		if not guid: 
			guid = self.get_preferred_guid()

		if guid:
			return self.get_password(guid)

	def get_dpapi_hash(self, sid, context='local'):
		"""
		Extract the DPAPI hash corresponding to the user's password to be able to bruteforce it using john or hashcat. 
		No admin privilege are required to extract it.
		:param context: expect local or domain depending of the windows environment. 
		"""

		self.get_preferred_guid()
		
		for mkfile in self.mkfiles:
			if self.preferred_guid == mkfile.mkf.guid:
				return mkfile.jhash(sid=sid, context=context)
				break

	def add_system_credential(self, blob):
		"""
		Adds DPAPI_SYSTEM token to the pool.
		blob is a string representing the LSA secret token
		"""
		self.system = CredSystem(blob)

	def try_credential(self, sid, password=None):
		"""
		This function tries to decrypt every masterkey contained in the pool that has not been successfully decrypted yet with the given password and SID.
		Should be called as a generator (ex: for r in try_credential(sid, password))
		"""

		# All master key files have been already decrypted
		if self.nb_mkf_decrypted == self.nb_mkf:
			raise StopIteration()
		
		for mkfile in self.mkfiles:
			if not mkfile.decrypted:
				mk = mkfile.mk
				mk.decrypt_with_password(sid, password)
				if not mk.decrypted and self.credhists.get(sid) is not None:
					# Try using credhist file
					self.credhists[sid].decrypt_with_password(password)
					for credhist in self.credhists[sid].entries_list:
						mk.decrypt_with_hash(sid, credhist.pwdhash)
						if credhist.ntlm is not None and not mk.decrypted:
							mk.decrypt_with_hash(sid, credhist.ntlm)
						
						if mk.decrypted:
							yield u'masterkey {masterkey} decrypted using credhists key'.format(masterkey=mkfile.mkf.guid)
							self.credhists[sid].valid = True
				
				if mk.decrypted:
					# Save the password found
					self.keys[mkfile.mkf.guid]['password'] 	= password
					mkfile.decrypted 		= True
					self.nb_mkf_decrypted 	+= 1

					yield u'{password} ok for masterkey {masterkey}'.format(password=password, masterkey=mkfile.mkf.guid)

				else:
					yield u'{password} not ok for masterkey {masterkey}'.format(password=password, masterkey=mkfile.mkf.guid)

	def try_credential_hash(self, sid, pwdhash=None):
		"""
		This function tries to decrypt every masterkey contained in the pool that has not been successfully decrypted yet with the given password and SID.
		Should be called as a generator (ex: for r in try_credential_hash(sid, pwdhash))
		"""
		
		# All master key files have been already decrypted
		if self.nb_mkf_decrypted == self.nb_mkf:
			raise StopIteration()
		
		for mkfile in self.mkfiles:
			if not mkfile.decrypted:
				mk = mkfile.mk
				mk.decrypt_with_hash(sid, pwdhash)
				if not mk.decrypted and self.credhists.get(sid) is not None:
					# Try using credhist file
					self.credhists[sid].decrypt_with_hash(pwdhash)
					for credhist in self.credhists[sid].entries_list:
						mk.decrypt_with_hash(sid, credhist.pwdhash)
						if credhist.ntlm is not None and not mk.decrypted:
							mk.decrypt_with_hash(sid, credhist.ntlm)
						
						if mk.decrypted:
							yield u'masterkey {masterkey} decrypted using credhists key'.format(masterkey=mkfile.mkf.guid)
							self.credhists[sid].valid = True
							break

				if mk.decrypted:
					mkfile.decrypted 		= True
					self.nb_mkf_decrypted 	+= 1
					
					yield u'{hash} ok for masterkey {masterkey}'.format(hash=pwdhash, masterkey=mkfile.mkf.guid)
				else:
					yield u'{hash} not ok for masterkey {masterkey}'.format(hash=pwdhash, masterkey=mkfile.mkf.guid)

	def try_system_credential(self):
		"""
		Decrypt masterkey files from the system user using DPAPI_SYSTEM creds as key
		Should be called as a generator (ex: for r in try_system_credential())
		"""
		for mkfile in self.mkfiles:
			if not mkfile.decrypted:
				mk = mkfile.mk
				mk.decrypt_with_key(self.system.user)
				if not mk.decrypted:
					mk.decrypt_with_key(self.system.machine)
				
				if mk.decrypted:
					mkfile.decrypted 		= True
					self.nb_mkf_decrypted 	+= 1
					
					yield True, u'System masterkey decrypted for {masterkey}'.format(masterkey=mkfile.mkf.guid)
				else:
					yield False, u'System masterkey not decrypted for masterkey {masterkey}'.format(masterkey=mkfile.mkf.guid)