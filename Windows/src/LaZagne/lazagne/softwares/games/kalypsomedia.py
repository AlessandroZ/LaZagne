import os, re, base64
from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
import ConfigParser

class KalypsoMedia(ModuleInfo):
	def __init__(self):
		options = {'command': '-k', 'action': 'store_true', 'dest': 'kalypsomedia', 'help': 'kalypsomedia'}
		ModuleInfo.__init__(self, 'kalypsomedia', 'games', options)

	# xorstring(s, k)
	# xors the two strings
	def xorstring(self, s, k):
		return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s,k))
		
	def run(self, software_name = None):
		creds = []
		key = 'lwSDFSG34WE8znDSmvtwGSDF438nvtzVnt4IUv89'
		
		if constant.appdata:
			inifile =  '%s\\Kalypso Media\\Launcher\\launcher.ini' % constant.appdata

		elif 'APPDATA' in os.environ:
			inifile = os.environ['APPDATA'] + '\\Kalypso Media\\Launcher\\launcher.ini'
		else:
			print_debug('ERROR', 'The APPDATA environment variable is not defined.')
			return
		
		# The actual user details are stored in *.userdata files
		if not os.path.exists(inifile):
			print_debug('INFO', 'The Kalypso Media Launcher doesn\'t appear to be installed.')
			return
		
		config = ConfigParser.ConfigParser()
		config.read(inifile)
		values = {}
		
		values['Login'] = config.get('styx user','login')
		
		# get the encoded password
		cookedpw = base64.b64decode(config.get('styx user','password'));
		values['Password'] = self.xorstring(cookedpw, key)
		
		creds.append(values)
		
		return creds

					
				
