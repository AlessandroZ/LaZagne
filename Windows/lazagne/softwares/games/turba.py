# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import _winreg
import os

class Turba(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'turba', 'games', registry_used=True)
		
	def run(self, software_name=None):
		creds	= []
		results = None
		
		# Find the location of steam - to make it easier we're going to use a try block
		# 'cos I'm lazy
		try:
			with OpenKey(HKEY_CURRENT_USER, 'Software\Valve\Steam') as key:
				results = _winreg.QueryValueEx(key, 'SteamPath')
		except:
			pass
		
		if results:
			steampath = unicode(results[0])
			steamapps = steampath + u'\\SteamApps\common'
			
			# Check that we have a SteamApps directory
			if not os.path.exists(steamapps):
				print_debug('ERROR', 'Steam doesn\'t have a SteamApps directory.')
				return
			
			filepath = steamapps + u'\\Turba\\Assets\\Settings.bin'
			
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
