# Thanks to the awesome work harmjoy
# For more information http://www.harmj0y.net/blog/redteaming/keethief-a-case-study-in-attacking-keepass-part-2/

# Thanks for the great work of libkeepass (used to decrypt keepass file)
# https://github.com/phpwutz/libkeepass

from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.write_output import print_debug
from lazagne.config.powershell_execute import powershell_execute
from lazagne.config.constant import *
import libkeepass

class Keepass(ModuleInfo):
	def __init__(self):
		options = {'command': '-k', 'action': 'store_true', 'dest': 'keepass', 'help': 'retrieve keepass password using KeeThief'}
		ModuleInfo.__init__(self, 'keepass', 'memory', options)

	def run(self, software_name = None):
		# password found on the memory dump class
		if constant.keepass:
			try:
				with libkeepass.open(constant.keepass['Database'], password=constant.keepass['Password'], keyfile=constant.keepass['KeyFilePath']) as kdb:
					pwdFound = kdb.to_dic()
				return pwdFound
			except:
				pass