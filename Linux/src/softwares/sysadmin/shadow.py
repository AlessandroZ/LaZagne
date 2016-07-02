import os,sys
import crypt
from config.header import Header
from config.write_output import print_debug, print_output
from config.moduleInfo import ModuleInfo
from config.dico import get_dico
from config.constant import *
from itertools import product

class Shadow(ModuleInfo): 

	def __init__(self):
		# Manage options
		options = {'command': '-s', 'action': 'store_true', 'dest': 'shadow', 'help': '/etc/shadow - Need root Privileges'}
		ModuleInfo.__init__(self, 'shadow', 'sysadmin', options)	

		self.filestr = '/etc/shadow'
		self.hash = '\n'
		self.pwdFound = []

	# used for dictionary attack, if user specify a specific file
	def get_dic(self, dictionary_path):
		words = []
		if dictionary_path:
			try:
				dicFile = open (dictionary_path,'r')
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
				print_debug('ERROR', 'Unable to open passwords file: %s' % str(self.dictionary_path))
				return []

			for word in dicFile.readlines():
				words.append(word.strip('\n'))
			dicFile.close()
		return words

	def attack(self, user, cryptPwd):
		# By default 500 most famous passwords are used for the dictionary attack 
		dic = get_dico()
		# add the user on the list to found weak password (login equal password)
		dic.insert(0, user)

		# file for dictionary attack entered 
		if constant.path:
			if os.path.exists(constant.path):
				dic = self.get_dic(constant.path)
			else:
				print_debug('WARNING', 'The file does not exist: %s' %  str(constant.path))
		
		# Different possible hash type	
		# ID  | Method
		# --------------------------------------------------------------------------
		# 1   | MD5
		# 2   | Blowfish (not in mainline glibc; added in some Linux distributions)
		# 5   | SHA-256 (since glibc 2.7)
		# 6   | SHA-512 (since glibc 2.7)
		
		hashType = cryptPwd.split("$")[1]
		values = {'Category': 'System Account'}
		
		if hashType == '1': # MD5
			print_debug('INFO', '[+] Hash type MD5 detected ...')
		elif hashType == '2':
			print_debug('INFO', '[+] Hash type Blowfish detected ...')
		elif hashType == '5':
			print_debug('INFO', '[+] Hash type SHA-256 detected ...')
		elif hashType == '6': # ShA-512 => used by all modern computers
			print_debug('INFO', '[+] Hash type SHA-512 detected ...')

		salt = cryptPwd.split("$")[2]
		realSalt = "$" + hashType + "$" + salt + "$"
		
		# -------------------------- Dictionary attack --------------------------
		print_debug('INFO', 'Dictionary Attack on the hash !!! ')
		try:
			for word in dic:
				try:
					cryptWord = crypt.crypt(word, realSalt)
				except Exception,e:
					print_debug('DEBUG', '{0}'.format(e))
					cryptWord = ''

				if cryptWord == cryptPwd:
					values['User'] = user
					values['password'] = word
					self.pwdFound.append(values)
					return
		except (KeyboardInterrupt, SystemExit):
			print 'INTERRUPTED!'
			print_debug('DEBUG', 'Dictionary attack interrupted')
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))

		print_debug('INFO', 'No password found using this attack !!! ')

	def root_access(self):
		if os.getuid() != 0:
			print_debug('INFO', 'You need more privileges (run it with sudo)\n')
			return False
		return True

	def check_file_access(self):
		if not os.path.exists(self.filestr):
			print_debug('WARNING', 'The path "%s" does not exist' % s(self.filestr))
			return False
		return True

	def run(self):
		Header().title_info('System account (from /etc/shadow)')

		# check root access
		if self.root_access():
			if self.check_file_access():
				shadowFile = open (self.filestr,'r')
				for line in shadowFile.readlines():
					_hash = line.replace('\n', '')
					
					line = _hash.split(':')

					# check if a password is defined
					if not line[1] in [ 'x', '*','!' ]:
						user = line[0]
						cryptPwd = line[1]
						
						# save each hash non empty
						self.hash += _hash + '\n'

						# try dictionary and bruteforce attack 
						self.attack(user, cryptPwd)
				
				values = {'Category' : 'Hash', 'Hash' : self.hash }
				self.pwdFound.append(values)
				
				# print the results
				print_output('System account (from /etc/shadow)', self.pwdFound)
