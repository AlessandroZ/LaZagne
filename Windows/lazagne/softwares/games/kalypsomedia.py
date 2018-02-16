# -*- coding: utf-8 -*- 
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import ConfigParser
import base64
import os

class KalypsoMedia(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'kalypsomedia', 'games')

	# xorstring(s, k)
	# xors the two strings
	def xorstring(self, s, k):
		return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s,k))
		
	def run(self, software_name=None):
		creds 	= []
		key 	= 'lwSDFSG34WE8znDSmvtwGSDF438nvtzVnt4IUv89'
		inifile = constant.profile['APPDATA'] + u'\\Kalypso Media\\Launcher\\launcher.ini'
		
		# The actual user details are stored in *.userdata files
		if os.path.exists(inifile):
			config = ConfigParser.ConfigParser()
			config.read(inifile)
			
			# get the encoded password
			cookedpw = base64.b64decode(config.get('styx user','password'));

			creds.append(
				{
					'Login'		: 	config.get('styx user','login'),
					'Password'	:	self.xorstring(cookedpw, key)
				}
			)
			return creds