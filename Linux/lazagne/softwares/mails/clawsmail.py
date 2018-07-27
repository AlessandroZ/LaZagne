#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Thanks to https://github.com/b4n/clawsmail-password-decrypter
from base64 import standard_b64decode as b64decode
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.crypto.pyDes import *
from lazagne.config import homes
import platform
import os

try: 
	from ConfigParser import ConfigParser 	# Python 2.7
except: 
	from configparser import ConfigParser	# Python 3


CFB = 0 # To implement

class ClawsMail(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'clawsmail', 'mails')

	def run(self, software_name=None):
		all_passwords = []
		for path in self.get_paths():
			mode = CFB
			if 'FreeBSD' in platform.system():
				mode = ECB

			all_passwords += self.accountrc_decrypt(path, self.get_passcrypt_key(), mode)

		return all_passwords

	def get_paths(self):
		return homes.get(file='.claws-mail/accountrc')

	def get_passcrypt_key(self):
		PASSCRYPT_KEY = b'passkey0'
		return PASSCRYPT_KEY

	def pass_decrypt(self, p, key, mode=CFB):
		""" Decrypts a password from ClawsMail. """
		if p[0] == '!':	 # encrypted password
			buf = b64decode(p[1:])

			"""
			If mode is ECB or CBC and the length of the data is wrong, do nothing
			as would the libc algorithms (as they fail early).	Yes, this means the
			password wasn't actually encrypted but only base64-ed.
			"""
			if (mode in (ECB, CBC)) and ((len(buf) % 8) != 0 or len(buf) > 8192):
				return buf

			# c = DES.new(key, mode=mode, IV=b'\0'*8)
			c = des(key, mode, b'\0'*8)
			return c.decrypt(buf)
		else:  # raw password
			return p


	def accountrc_decrypt(self, filename, key, mode=CFB):
		""" Reads passwords from ClawsMail's accountrc file """
		p = ConfigParser()
		p.read(filename)

		pwdFound = []
		for s in p.sections():
			values = {}
			try:
				try:
					address = p.get(s, 'address')
					account = p.get(s, 'account_name')
				except:
					address = '<unknown>'
					account = '<unknown>'

				password = self.pass_decrypt(p.get(s, 'password'), key, mode=mode)
				values = {'Login' : account, 'URL': address, 'Password': password}
			except Exception as e:
				print_debug('ERROR', 'Error resolving password for account "%s": %s' % (s, e))

			 # write credentials into a text file
			if len(values) != 0:
				pwdFound.append(values)

		return pwdFound
