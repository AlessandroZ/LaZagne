from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import base64
import os

class Unattended(ModuleInfo):
	def __init__(self):
		options = {'command': '-u', 'action': 'store_true', 'dest': 'unattended', 'help': 'unattended file'}
		ModuleInfo.__init__(self, 'unattended', 'sysadmin', options, need_to_be_in_env=False)

	# Password should be encoded in b64
	def try_b64_decode(self, message):
		try:
			return base64.b64decode(message)
		except:
			return message

	def run(self, software_name = None):		
		# realise that check only once 
		if constant.checkUnattended:
			return 

		constant.checkUnattended = True
		windir = os.path.join(constant.profile['HOMEDRIVE'], '\Windows')
		files = [
			"\Panther\Unattend.xml",
			"\Panther\Unattended.xml", 
			"\Panther\Unattend\Unattended.xml", 
			"\Panther\Unattend\Unattend.xml", 
			"\System32\Sysprep\unattend.xml", 
			"\System32\Sysprep\Panther\unattend.xml"
		]

		pwdFound = []
		xmlns = '{urn:schemas-microsoft-com:unattend}'
		for file in files:
			path = '%s%s' % (windir, file)
			if os.path.exists(path):
				print_debug('INFO', 'Unattended file found: %s' % path)
				tree = ET.ElementTree(file=path)
				root = tree.getroot()
				
				for setting in root.findall('%ssettings' % xmlns):
					component = setting.find('%scomponent' % xmlns)
					
					autoLogon = component.find('%sAutoLogon' % xmlns)
					if autoLogon != None:
						username = autoLogon.find('%sUsername' % xmlns)
						password = autoLogon.find('%sPassword' % xmlns)
						if username != None and password != None:
							# Remove false positive (with following message on password => *SENSITIVE*DATA*DELETED*)
							if not 'deleted' in password.text.lower():
								pwdFound.append(
									{
										'Login' 	: username.text,
										'Password'	: self.try_b64_decode(password.text)
									}
								)
					
					userAccounts = component.find('%sUserAccounts' % xmlns)
					if userAccounts != None:
						localAccounts = userAccounts.find('%sLocalAccounts' % xmlns)
						if localAccounts != None:
							for localAccount in localAccounts.findall('%sLocalAccount' % xmlns):
								username = localAccount.find('%sName' % xmlns)
								password = localAccount.find('%sPassword' % xmlns)
								if username != None and password != None:
									if not 'deleted' in password.text.lower():
										pwdFound.append(
											{
												'Login' 	: username.text,
												'Password'	: self.try_b64_decode(password.text)
											}
										)

		return pwdFound