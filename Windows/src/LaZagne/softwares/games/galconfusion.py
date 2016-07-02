import os
from _winreg import HKEY_CURRENT_USER, OpenKey, QueryValueEx
from config.constant import *
from config.write_output import print_output, print_debug
from config.header import Header
from config.moduleInfo import ModuleInfo

class GalconFusion(ModuleInfo):
	def __init__(self):
		options = {'command': '-g', 'action': 'store_true', 'dest': 'galconfusion', 'help': 'galconfusion'}
		ModuleInfo.__init__(self, 'galconfusion', 'games', options)
		
	def run(self):
		# print title
		Header().title_info('Galcon Fusion')
		creds = []
		
		# Find the location of steam - to make it easier we're going to use a try block
		# 'cos I'm lazy
		try:
			with OpenKey(HKEY_CURRENT_USER, 'Software\Valve\Steam') as key:
				results=QueryValueEx(key, 'SteamPath')
		except:
			print_debug('INFO', 'Steam does not appear to be installed.')
			return
		
		if not results:
			print_debug('INFO', 'Steam does not appear to be installed.')
			return
			
		steampath=results[0]
		userdata = steampath + '\\userdata'
		
		# Check that we have a userdata directory
		if not os.path.exists(userdata):
			print_debug('ERROR', 'Steam doesn\'t have a userdata directory.')
			return
		
		# Now look for Galcon Fusion in every user
		files = os.listdir(userdata)
		
		for file in files:
			filepath = userdata + '\\' + file + '\\44200\\remote\\galcon.cfg'
			if not os.path.exists(filepath):
				continue
			
			# If we're here we should have a Galcon Fusion file
			with open(filepath, mode='rb') as cfgfile: 
				# We've found a config file, now extract the creds
				data = cfgfile.read()
				values = {}
				
				values['Login'] = data[4:0x23]
				values['Password'] = data[0x24:0x43]
				creds.append(values)
		
		print_output("Galcon Fusion", creds)
					
				
