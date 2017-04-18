from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import _winreg
import os

class Turba(ModuleInfo):
	def __init__(self):
		options = {'command': '-t', 'action': 'store_true', 'dest': 'turba', 'help': 'turba'}
		ModuleInfo.__init__(self, 'turba', 'games', options, cannot_be_impersonate_using_tokens=True)
		
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
		steamapps = steampath + '\\SteamApps\common'
		
		# Check that we have a SteamApps directory
		if not os.path.exists(steamapps):
			print_debug('ERROR', 'Steam doesn\'t have a SteamApps directory.')
			return
		
		filepath = steamapps + '\\Turba\\Assets\\Settings.bin'
		
		if not os.path.exists(filepath):
			print_debug('INFO', 'Turba doesn\'t appear to be installed.')
			return
			
		# If we're here we should have a valid config file file
		with open(filepath, mode='rb') as filepath: 
			# We've found a config file, now extract the creds
			data = filepath.read()
			chunk=data[0x1b:].split('\x0a')
			creds.append(
				{
					'Login'		: chunk[0], 
					'Password'	: chunk[1]
				}
			)		
		return creds
