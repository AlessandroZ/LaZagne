# -*- coding: utf-8 -*- 
from lazagne.config.dpapi.preferred import display_masterkey
from lazagne.config.dpapi.creddec import decrypt_user_cred
from lazagne.config.dpapi.DPAPI.Core import masterkey
from lazagne.config.write_output import print_debug
from lazagne.config.constant import *
import traceback
import os

class Decrypt_DPAPI():
	def __init__(self, password=None, pwdhash=None):
		self.sid 					= None
		self.preferred_umkp 		= None
		self.dpapi_ok 				= False
		self.umkp 					= None
		self.smkp 					= None
		self.last_masterkey_file	= None
		adding_missing_path 		= ''
		
		# -------------------------- User Information --------------------------

		protect_folder = os.path.join(constant.profile['APPDATA'], u'Microsoft', u'Protect')
		if os.path.exists(protect_folder):
			for folder in os.listdir(protect_folder):
				if folder.startswith('S-'):
					self.sid = folder

			masterkeydir 	= os.path.join(protect_folder, self.sid)
			if os.path.exists(masterkeydir):
				# user master key pool
				self.umkp = masterkey.MasterKeyPool()
				
				# load all master key files (not only the one contained on preferred)
				self.umkp.loadDirectory(masterkeydir)

				preferred_file = os.path.join(masterkeydir, 'Preferred')
				if os.path.exists(preferred_file):
					preferred_mk_guid 	= display_masterkey(open(preferred_file, 'rb'))
					
					# Preferred file contains the GUID of the last mastekey created
					self.last_masterkey_file	= os.path.join(masterkeydir, preferred_mk_guid)
					if os.path.exists(self.last_masterkey_file):
						print_debug('DEBUG', 'Last masterkey created: {masterkefile}'.format(masterkefile=self.last_masterkey_file))
						self.preferred_umkp = masterkey.MasterKeyPool()
						self.preferred_umkp.addMasterKey(open(self.last_masterkey_file, 'rb').read())

				credhist_path 	= os.path.join(constant.profile['APPDATA'], u'Microsoft', u'Protect', u'CREDHIST')
				credhist		= credhist_path if os.path.exists(credhist_path) else None
				
				if credhist:
					self.umkp.addCredhistFile(self.sid, credhist)
				
				if password:
					if self.umkp.try_credential(self.sid, password):
						self.dpapi_ok = True
					else:
						print_debug('DEBUG', 'Password not correct: {password}'.format(password=password))


	def check_credentials(self, passwords):
		# the password is tested if possible only on the last masterkey file created by the system (visible on the preferred file) to avoid false positive
		# if tested on all masterkey files, it could retrieve a password without to be able to decrypt a blob (happenned on my host :))
		# mk = self.preferred_umkp if self.preferred_umkp is not None else self.umkp
		if self.preferred_umkp:
			self.umkp = self.preferred_umkp

		if self.umkp:
			for password in passwords:
				print_debug('INFO', 'Check password: {password}'.format(password=password))
				if self.umkp.try_credential(self.sid, password):
					print_debug('INFO', 'User password found: {password}\n'.format(password=password))
					self.dpapi_ok = True
					return password

		return False

	def decrypt_cred(self, cred_file):
		if self.dpapi_ok:
			ok, msg = decrypt_user_cred(umkp=self.umkp, cred_file=cred_file)
			if ok: 
				return msg
			else:
				print_debug('DEBUG', msg)
		else:
			print_debug('INFO', 'Passwords have not been retrieved. User password seems to be wrong ')
		
		return False

	def get_DPAPI_hash(self, context='local'):
		if self.umkp:
			self.umkp.get_john_hash(masterkeyfile=self.last_masterkey_file, sid=self.sid, context=context)

