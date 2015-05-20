import win32con, win32api, win32cred
import struct, hashlib, os, base64
from ctypes import *
from ctypes.wintypes import DWORD
from config.constant import *
from config.write_output import print_output, print_debug
from config.header import Header
from config.moduleInfo import ModuleInfo

memcpy = cdll.msvcrt.memcpy
LocalFree = windll.kernel32.LocalFree
CryptUnprotectData = windll.crypt32.CryptUnprotectData
CRYPTPROTECT_UI_FORBIDDEN = 0x01

dll_name = "web_history.dll"
pwdFound = []

class DATA_BLOB(Structure):
	_fields_ = [
		('cbData', DWORD),
		('pbData', POINTER(c_char))
	]

class IE(ModuleInfo):
	def __init__(self):
		options = {'command': '-e', 'action': 'store_true', 'dest': 'ie', 'help': 'internet explorer from version 7 to 11 (but not with win8)'}
		suboptions = [{'command': '-l', 'action': 'store', 'dest': 'historic', 'help': 'text file with a list of websites', 'title': 'Advanced ie option'}]
		ModuleInfo.__init__(self, 'ie', 'browsers', options, suboptions)

	def getData(self, blobOut):
		cbData = int(blobOut.cbData)
		pbData = blobOut.pbData
		buffer = c_buffer(cbData)
		
		memcpy(buffer, pbData, cbData)
		LocalFree(pbData);
		return buffer.raw

	def Win32CryptUnprotectData(self, cipherText, entropy):
		bufferIn = c_buffer(cipherText, len(cipherText))
		blobIn = DATA_BLOB(len(cipherText), bufferIn)
		bufferEntropy = c_buffer(entropy, len(entropy))
		blobEntropy = DATA_BLOB(len(entropy), bufferEntropy)
		blobOut = DATA_BLOB()
		if CryptUnprotectData(byref(blobIn), None, byref(blobEntropy), None, None, 0, byref(blobOut)):
			return self.getData(blobOut)
		else:
			return 'failed'

	def get_hash_table(self, list):
		# get the url list
		urls = self.get_history()
		urls = urls + list
		
		# calculate the hash for all urls found on the history
		hash_tables = []
		for u in range(len(urls)):
			try:
				h = (urls[u] + '\0').encode('UTF-16LE')
				hash_tables.append([h, hashlib.sha1(h).hexdigest().lower()])
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
		return hash_tables

	def write_binary_file(self):
		coded_string = '''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
AAAAAPIjAAAgJAAALiQAADYkAABAJAAA3CMAAMojAAC8IwAAriMAAKIjAACSIwAAiiMAAHwjAABe
IwAAUiMAAEgjAAAWJAAAAAAAAC4jAAAcIwAACCMAAAAAAAAAAAAAAAAAAAAAAAA6EQAQAAAAAAAA
AADBgstUAAAAAAIAAABZAAAAQCEAAEAPAABASjc85LrPEb99AKoAaUbuEdygrxPD0BGDGgDAT9Wu
OAAAAAAYMAAQcDAAEEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAwABCgIQAQAQAAAFJTRFNf/rybQ84IRoElotmj42K4LQAAAEM6XFVz
ZXJzXEpvaG5cRGVza3RvcFxMYXphZ25lX3Rlc3RcaGlzdG9yaWNcUmVsZWFzZVxoaXN0b3JpYy5w
ZGIAAAAAAAAAANkYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP7///8AAAAA0P///wAAAAD+////AAAA
AJ0UABAAAAAAaRQAEH0UABD+////AAAAAMz///8AAAAA/v///wAAAAB1FgAQAAAAAP7///8AAAAA
2P///wAAAAD+////CxgAEB4YABD4IgAAAAAAAAAAAAA+IwAAjCAAALAiAAAAAAAAAAAAAG4jAABE
IAAAbCIAAAAAAAAAAAAAuCUAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJ4lAACIJQAAciUAAEgl
AAAsJQAAGCUAAPokAADeJAAAyiQAALYkAACYJAAAkCQAAHokAABqJAAAWiQAAGIlAAAAAAAA8iMA
ACAkAAAuJAAANiQAAEAkAADcIwAAyiMAALwjAACuIwAAoiMAAJIjAACKIwAAfCMAAF4jAABSIwAA
SCMAABYkAAAAAAAALiMAABwjAAAIIwAAAAAAABAAQ29DcmVhdGVJbnN0YW5jZQAAbABDb1VuaW5p
dGlhbGl6ZQAAPgBDb0luaXRpYWxpemUAAG9sZTMyLmRsbAAwBndjc2NocgAANAZ3Y3NjcHlfcwAA
YwA/PzJAWUFQQVhJQFoAAE1TVkNSMTAwLmRsbAAANANfbWFsbG9jX2NydACLBWZyZWUAABkCX2Vu
Y29kZWRfbnVsbACwAl9pbml0dGVybQCxAl9pbml0dGVybV9lAMUBX2Ftc2dfZXhpdAAAMQFfX0Nw
cFhjcHRGaWx0ZXIA+wFfY3J0X2RlYnVnZ2VyX2hvb2sAAFMBX19jbGVhbl90eXBlX2luZm9fbmFt
ZXNfaW50ZXJuYWwAAI0EX3VubG9jawBbAV9fZGxsb25leGl0ACMDX2xvY2sAyQNfb25leGl0ACEC
X2V4Y2VwdF9oYW5kbGVyNF9jb21tb24A6gBFbmNvZGVQb2ludGVyAMoARGVjb2RlUG9pbnRlcgDs
AkludGVybG9ja2VkRXhjaGFuZ2UAsgRTbGVlcADpAkludGVybG9ja2VkQ29tcGFyZUV4Y2hhbmdl
AADABFRlcm1pbmF0ZVByb2Nlc3MAAMABR2V0Q3VycmVudFByb2Nlc3MA0wRVbmhhbmRsZWRFeGNl
cHRpb25GaWx0ZXIAAKUEU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAAADSXNEZWJ1Z2dlclBy
ZXNlbnQA3gBEaXNhYmxlVGhyZWFkTGlicmFyeUNhbGxzAKcDUXVlcnlQZXJmb3JtYW5jZUNvdW50
ZXIAkwJHZXRUaWNrQ291bnQAAMUBR2V0Q3VycmVudFRocmVhZElkAADBAUdldEN1cnJlbnRQcm9j
ZXNzSWQAeQJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQBLRVJORUwzMi5kbGwAAAAAAAAAAAAAAAAA
AAAAwYLLVAAAAAACJgAAAQAAAAEAAAABAAAA+CUAAPwlAAAAJgAAIBEAAA8mAAAAAGhpc3Rvcmlj
LmRsbABsaXN0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE7mQLuxGb9E////
//////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAA
AAABABgAAAAYAACAAAAAAAAAAAAEAAAAAAABAAIAAAAwAACAAAAAAAAAAAAEAAAAAAABAAkEAABI
AAAAWEAAAFoBAADkBAAAAAAAADxhc3NlbWJseSB4bWxucz0idXJuOnNjaGVtYXMtbWljcm9zb2Z0
LWNvbTphc20udjEiIG1hbmlmZXN0VmVyc2lvbj0iMS4wIj4NCiAgPHRydXN0SW5mbyB4bWxucz0i
dXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTphc20udjMiPg0KICAgIDxzZWN1cml0eT4NCiAgICAg
IDxyZXF1ZXN0ZWRQcml2aWxlZ2VzPg0KICAgICAgICA8cmVxdWVzdGVkRXhlY3V0aW9uTGV2ZWwg
bGV2ZWw9ImFzSW52b2tlciIgdWlBY2Nlc3M9ImZhbHNlIj48L3JlcXVlc3RlZEV4ZWN1dGlvbkxl
dmVsPg0KICAgICAgPC9yZXF1ZXN0ZWRQcml2aWxlZ2VzPg0KICAgIDwvc2VjdXJpdHk+DQogIDwv
dHJ1c3RJbmZvPg0KPC9hc3NlbWJseT5QQVBBRERJTkdYWFBBRERJTkdQQURESU5HWFhQQURESU5H
UEFERElOR1hYUEFERElOR1BBRERJTkdYWFBBRERJTkdQQURESU5HWFhQQUQAEAAAGAEAAA8wGDAg
MCYwTDB6ML0wzTDUMAkxJjEtMUQxTjFTMVgxbjF6MZsxqTG2Mbsx4THqMfsxEzIoMi0yMzJLMlAy
XDJsMnIyeTKQMpYyqjLCMtoy4DLzMhMzJDMvMzczXzNmM2szcDN3M4QzlTOyM78z1zMqNFc0nzTX
NN004zTpNO809TT8NAM1CjURNRg1HzUmNS41NjU+NUo1UzVYNV41aDVxNXw1iDWNNZ01ojWoNa41
xDXLNdI14DXrNfE1BDYZNiQ2OjZSNlw2mTaeNr82xDaIN403nze9N9E31zc+OEQ4SjhQOGE4bTiB
OJ446zjwOAc5Kjk3OUM5SzlTOV85iDmQOZw5ojmoOa45tDm6OQAAACAAACAAAACoMPAw9DA0MTgx
0DHYMdwx+DEUMhgyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='''

		f = open(dll_name, 'wb')
		f.write(base64.b64decode(coded_string))
		f.close()

	def get_history(self):
		urls = []
		urls = self.history_from_regedit()
		
		try:
			# wrapper to call the dll exported function (called list)
			lib = cdll.LoadLibrary(dll_name)
			lib.list.restype = POINTER(c_wchar_p)
			ret = lib.list()

			for r in ret:
				try:
					if r:
						if r.startswith("http") and r not in urls:
							urls.append(r)
					else:
						break
				except Exception,e:
					print_debug('DEBUG', '{0}'.format(e))
		
			# Unload the dll to delete it later
			handle = lib._handle # obtain the DLL handle
			windll.kernel32.FreeLibrary(handle)
			
			# delete the dll
			os.remove(dll_name)
			
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			print_debug('ERROR', 'Browser history failed to load, only few url will be tried')
		
		urls.append('https://www.facebook.com/')
		urls.append('https://www.gmail.com/')
		urls.append('https://accounts.google.com/')
		urls.append('https://accounts.google.com/servicelogin')
		
		return urls
	
	def history_from_regedit(self):
		urls = []
		
		# open the registry
		accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
		keyPath = 'Software\\Microsoft\\Internet Explorer\\TypedURLs'
		
		try:
			hkey = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, keyPath, 0, accessRead)
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			return []
		
		num = win32api.RegQueryInfoKey(hkey)[1]
		for x in range(0, num):
			k = win32api.RegEnumValue(hkey, x)
			if k:
				urls.append(k[1])
		return urls
		
	def decipher_password(self, cipher_text, u):
		# deciper the password
		pwd = self.Win32CryptUnprotectData(cipher_text, u)
		a = None
		for i in range(len(pwd)):
			try:
				a = pwd[i:].decode('UTF-16LE')
				a = a.decode('utf-8')
				break
			except Exception,e:
				pass
				result = ''
		
		# the last one is always equal to 0
		secret = a.split('\x00')
		if secret[len(secret)-1] == '':
			secret = secret[:len(secret)-1]

		# define the length of the tab
		if len(secret) % 2 == 0:
			length = len(secret)
		else: 
			length = len(secret)-1

		values = {}
		# list username / password in clear text
		for s in range(length):
			try:
				if s % 2 != 0:
					values = {}
					values['Site'] = u.decode('UTF-16LE')
					values['Username'] = secret[length - s]
					values['Password'] = password
					pwdFound.append(values)
				else:
					password = secret[length - s]
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
	
	def run(self, historic=''):
		# print title
		Header().title_info('Internet Explorer')
		
		# write the binary file
		try:
			self.write_binary_file()
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			print_debug('ERROR', '%s cannot be created, check your file permission' % dll_name)
		
		list = []
		if historic:
			if os.path.exists(historic):
				f = open(historic, 'r')
				for line in f:
					list.append(line.strip())
			else:
				print_debug('WARNING', 'The text file %s does not exist' % historic)
		
		# retrieve the urls from the history
		hash_tables = self.get_hash_table(list)
		
		# open the registry
		accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
		keyPath = 'Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2'
		
		failed = False
		try:
			hkey = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, keyPath, 0, accessRead)
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			failed = True
		
		nb_site = 0
		nb_pass_found = 0 
		if failed == False:
			num = win32api.RegQueryInfoKey(hkey)[1]
			for x in range(0, num):
				k = win32api.RegEnumValue(hkey, x)
				if k:
					nb_site +=1
					for h in hash_tables:
						# both hash are similar, we can decipher the password
						if h[1] == k[0][:40].lower():
							nb_pass_found += 1
							cipher_text = k[1]
							self.decipher_password(cipher_text, h[0])
							break
			
			# print the results
			print_output("Internet Explorer", pwdFound)
			
			# manage errors
			if nb_site == 0:
				print_debug('INFO', 'No credentials stored in the IE browser.')
			elif nb_site > nb_pass_found:
				print_debug('ERROR', '%s hashes have not been decrypted, the associate website used to decrypt the passwords has not been found' % str(nb_site - nb_pass_found))
			
		else:
			print_debug('INFO', 'No password stored.\nThe registry key storing the ie password has not been found.\nKey: %s' % keyPath)

