from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import _winreg
import os

class GalconFusion(ModuleInfo):
	def __init__(self):
		options = {'command': '-g', 'action': 'store_true', 'dest': 'galconfusion', 'help': 'galconfusion'}
		ModuleInfo.__init__(self, 'galconfusion', 'games', options, cannot_be_impersonate_using_tokens=True)
		
	def run(self, software_name = None):
		creds = []
		
		# Find the location of steam - to make it easier we're going to use a try block
		# 'cos I'm lazy
		try:
			with _winreg.OpenKey(HKEY_CURRENT_USER, 'Software\Valve\Steam') as key:
				results = _winreg.QueryValueEx(key, 'SteamPath')
		except:
			print_debug('INFO', 'Steam does not appear to be installed.')
			return
		
		if not results:
			print_debug('INFO', 'Steam does not appear to be installed.')
			return
			
		steampath = results[0]
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
				creds.append(
					{
						'Login'		: 	data[4:0x23],
						'Password'	: 	data[0x24:0x43]
					}
				)
		
		return creds
