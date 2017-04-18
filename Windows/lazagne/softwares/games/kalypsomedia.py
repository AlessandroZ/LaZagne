from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import ConfigParser
import base64
import os

class KalypsoMedia(ModuleInfo):
	def __init__(self):
		options = {'command': '-k', 'action': 'store_true', 'dest': 'kalypsomedia', 'help': 'kalypsomedia'}
		ModuleInfo.__init__(self, 'kalypsomedia', 'games', options, need_to_be_in_env=False)

	# xorstring(s, k)
	# xors the two strings
	def xorstring(self, s, k):
		return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s,k))
		
	def run(self, software_name = None):
		creds = []
		key = 'lwSDFSG34WE8znDSmvtwGSDF438nvtzVnt4IUv89'
		inifile = constant.profile['APPDATA'] + '\\Kalypso Media\\Launcher\\launcher.ini'
		
		# The actual user details are stored in *.userdata files
		if not os.path.exists(inifile):
			print_debug('INFO', 'The Kalypso Media Launcher doesn\'t appear to be installed.')
			return
		
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