from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import base64
import os 

class Tortoise(ModuleInfo):
	def __init__(self):
		options = {'command': '-t', 'action': 'store_true', 'dest': 'tortoise', 'help': 'tortoise'}
		ModuleInfo.__init__(self, 'tortoise', 'svn', options)

	# main function
	def run(self, software_name = None):	
		pwdFound = []
		
		file_path = os.path.join(constant.profile["APPDATA"], 'Subversion\\auth\\svn.simple')
		if os.path.exists(file_path):
			for root, dirs, files in os.walk(file_path + os.sep):
				for name_file in files:
					f = open(file_path + os.sep + name_file, 'r')
					
					url = ''
					username = ''
					result = ''
					
					i = 0
					# password
					for line in f:
						if i == -1:
							result = line.replace('\n', '')
							break
						if line.startswith('password'):
							i = -3
						i+=1
					
					i = 0
					# url
					for line in f:
						if i == -1:
							url = line.replace('\n', '')
							break
						if line.startswith('svn:realmstring'):
							i = -3
						i+=1

					i = 0
					
					# username
					for line in f:
						if i == -1:
							username = line.replace('\n', '')
							break
						if line.startswith('username'):
							i = -3
						i+=1
					
					# encrypted the password
					if result:
						try:
							password = Win32CryptUnprotectData(base64.b64decode(result))
							pwdFound.append(
								{
									'URL'		: 	url, 
									'Login'		: 	username, 
									'Password'	: 	str(password)
								}
							)
						except:
							pass
			return pwdFound
		else:
			print_debug('INFO', 'Tortoise not installed.')
