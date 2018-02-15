# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import _winreg
import os

class GalconFusion(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'galconfusion', 'games', registry_used=True)
		
	def run(self, software_name=None):
		creds 	= []
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
			userdata = steampath + u'\\userdata'
			
			# Check that we have a userdata directory
			if not os.path.exists(userdata):
				print_debug('ERROR', 'Steam doesn\'t have a userdata directory.')
				return
			
			# Now look for Galcon Fusion in every user
			files = os.listdir(userdata)
			
			for file in files:
				filepath = userdata + u'\\' + unicode(file) + u'\\44200\\remote\\galcon.cfg'
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
