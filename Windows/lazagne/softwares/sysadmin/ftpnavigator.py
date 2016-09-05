import struct, os
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo

class FtpNavigator(ModuleInfo):
	def __init__(self):
		options = {'command': '-ftp', 'action': 'store_true', 'dest': 'ftpnavigator', 'help': 'FTP Navigator'}
		ModuleInfo.__init__(self, 'ftpnavigator', 'sysadmin', options)

	def decode(self, encode_password):
		password = ''
		for p in encode_password:
			password += chr(struct.unpack('B', p)[0] ^ 0x19)
		return password
	
	def read_file(self, filepath):
		f = open(filepath, 'r')
		pwdFound = []
		for ff in f.readlines():
			values = {}
			info = ff.split(';')
			for i in info:
				i = i.split('=')
				if i[0] == 'Name':
					values['Name'] = i[1]
				if i[0] == 'Server':
					values['Server'] =  i[1]
				if i[0] == 'Port':
					values['Port'] =  i[1]
				if i[0] == 'User':
					values['User'] = i[1]
				if i[0] == "Password":
					if i[1] != '1' and i[1] != '0':
						values['Password'] = self.decode(i[1])
			
			# used to save the password if it is an anonymous authentication
			if values['User'] == 'anonymous' and 'Password' not in values.keys():
				values['Password'] = 'anonymous'
			
			pwdFound.append(values)
		
		return pwdFound
		
	def run(self, software_name = None):
		if 'HOMEDRIVE' in os.environ:
			path = os.environ.get('HOMEDRIVE') + os.sep + 'FTP Navigator\\Ftplist.txt'
			
			if os.path.exists(path):
				return self.read_file(path)
			else:
				print_debug('INFO', 'Paht %s does not exist.\nFTP Navigator not installed or not found.' % path)

