### Code based on vncpasswd.py by trinitronx
###https://github.com/trinitronx/vncpasswd.py
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
import d3des as d
import _winreg
import binascii; 


class VNC(ModuleInfo):
	def __init__(self):
		options = {'command': '-vnc', 'action': 'store_true', 'dest': 'vnc', 'help': 'Try to get all VNC server passwords'}
		ModuleInfo.__init__(self, 'vnc', 'sysadmin', options)


	def split_len(self,seq, length):
		return [seq[i:i+length] for i in range(0, len(seq), length)]


	def do_crypt(self,password, decrypt):
		passpadd = (password + '\x00'*8)[:8]
		strkey = ''.join([chr(x) for x in d.vnckey])
		key = d.deskey(strkey, decrypt)
		crypted = d.desfunc(passpadd, key)
		return crypted


	def unhex(self, s):
		try:
			s = s.decode('hex')

		except TypeError as e:
			if e.message == 'Odd-length string':
				print 'WARN: %s . Chopping last char off... "%s"' % (e.message, s[:-1])
				s = s[:-1].decode('hex')

			else:
				raise

		return s


	def reverse_vncpassword(self, hash):
		#print_debug('INFO', hash)
		encpasswd = self.unhex(hash)
		# If the hex encoded passwd length is longer than 16 hex chars and divisible
		# by 16, then we chop the passwd into blocks of 64 bits (16 hex chars)
		# (1 hex char = 4 binary bits = 1 nibble)
		hexpasswd = encpasswd.encode('hex')
		if ( len(hexpasswd) > 16 and (len(hexpasswd) % 16) == 0 ):
			splitstr = split_len(hash.encode('hex'), 16)
			cryptedblocks = []
			for sblock in splitstr:
				cryptedblocks.append( self.do_crypt(sblock.decode('hex'), True) )
				pwd = ''.join(cryptedblocks)
		elif ( len(hexpasswd) <= 16):
			pwd = self.do_crypt(encpasswd, True)
		else:
			pwd = self.do_crypt(encpasswd, True) 
		#print_debug('INFO', pwd)
		return pwd


	def vnc_from_registry(self):
		pfound = []
		vncs = (
			('RealVNC 4.x','HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\RealVNC\\WinVNC4','Password'),
			('RealVNC 3.x','HKEY_LOCAL_MACHINE\\SOFTWARE\\RealVNC\\vncserver','Password'),
			('RealVNC 4.x','HKEY_CURRENT_USER\\SOFTWARE\\RealVNC\\WinVNC4','Password'),
			('RealVNC 3.x','HKEY_CURRENT_USER\\Software\\ORL\\WinVNC3','Password'),
			('TightVNC','HKEY_CURRENT_USER\\Software\\TightVNC\\Server','Password'),
			('TightVNC','HKEY_CURRENT_USER\\Software\\TightVNC\\Server','PasswordViewOnly'),
			('TightVNC','HKEY_LOCAL_MACHINE\\Software\\TightVNC\\Server','Password'),
			('TightVNC ControlPassword','HKEY_LOCAL_MACHINE\\Software\\TightVNC\\Server','ControlPassword'),
			('TightVNC','HKEY_LOCAL_MACHINE\\Software\\TightVNC\\Server','PasswordViewOnly'),
			('TigerVNC','HKEY_LOCAL_MACHINE\\Software\\TigerVNC\\Server','Password'),
			('TigerVNC','HKEY_CURRENT_USER\\Software\\TigerVNC\\Server','Password'),
		)

		for vnc in vncs:
			#print_debug('INFO', 'Server: ' + vnc[0] + ' Key: ' + vnc[1] + ' Value: ' + vnc[2])
			try:
				if vnc[1].startswith('HKEY_LOCAL_MACHINE'):
					hkey = OpenKey(HKEY_LOCAL_MACHINE,vnc[1].replace('HKEY_LOCAL_MACHINE\\',''))

				elif vnc[1].startswith('HKEY_CURRENT_USER'):
					hkey = OpenKey(HKEY_CURRENT_USER,vnc[1].replace('HKEY_CURRENT_USER\\',''))

				reg_key = _winreg.QueryValueEx(hkey,vnc[2])[0]

			except Exception, e:
				print_debug('INFO', 'Problems with key: ' + vnc[1])
				continue

			try:
				encpwd = binascii.hexlify(reg_key).decode()

			except Exception, e:
				print_debug('INFO', 'Problems with decoding: ' + reg_key)
				continue

			values = {}

			try:
				values['Password'] = self.reverse_vncpassword(encpwd)

			except Exception, e:
				print_debug('INFO', 'Problems with reverse_vncpassword: ' + reg_key)
				continue

			values['Server'] = vnc[0]
			#values['Hash'] = encpwd
			pfound.append(values)
		
		return pfound


	def vnc_from_filesystem(self):
		pfound = []
		vncs = (
			('UltraVNC',os.environ['ProgramFiles(x86)']+'\uvnc bvba\UltraVNC\ultravnc.ini','passwd'),
			('UltraVNC',os.environ['ProgramFiles(x86)']+'\uvnc bvba\UltraVNC\ultravnc.ini','passwd2'),
			('UltraVNC',os.environ['PROGRAMFILES']+'\uvnc bvba\UltraVNC\ultravnc.ini','passwd'),
			('UltraVNC',os.environ['PROGRAMFILES']+'\uvnc bvba\UltraVNC\ultravnc.ini','passwd2'),
			('UltraVNC',os.environ['PROGRAMFILES']+'\UltraVNC\ultravnc.ini','passwd'),
			('UltraVNC',os.environ['PROGRAMFILES']+'\UltraVNC\ultravnc.ini','passwd2'),
			('UltraVNC',os.environ['ProgramFiles(x86)']+'\UltraVNC\ultravnc.ini','passwd'),
			('UltraVNC',os.environ['ProgramFiles(x86)']+'\UltraVNC\ultravnc.ini','passwd2'),
		)

		for vnc in vncs:
			stringToMatch = vnc[2] + '='
			encpwd = ''
			try:
				with open(vnc[1], 'r') as file:
					for line in file:
						if stringToMatch in line:
							encpwd = line.replace(stringToMatch,'').replace('\n', '')
							
			except Exception, e:
				print_debug('INFO', 'Problems with file: ' + vnc[1])
				continue

			values = {}

			try:
				values['Password'] = self.reverse_vncpassword(encpwd)

			except Exception, e:
				print_debug('INFO', 'Problems with reverse_vncpassword: ' + reg_key)
				continue

			values['Server'] = vnc[0]
			#values['Hash'] = encpwd
			pfound.append(values)
		
		return pfound			


	def vnc_from_process(self):
		# Not yet implemented
		return []


	def run(self, software_name = None):		
		return self.vnc_from_filesystem() + self.vnc_from_registry() + self.vnc_from_process()
