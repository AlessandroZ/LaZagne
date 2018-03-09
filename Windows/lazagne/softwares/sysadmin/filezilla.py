# -*- coding: utf-8 -*- 
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import base64
import os

class Filezilla(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'filezilla', 'sysadmin')

	def run(self, software_name = None):		
		path = os.path.join(constant.profile['APPDATA'], u'FileZilla')
		if os.path.exists(path):
			pwdFound = []
			for file in [u'sitemanager.xml', u'recentservers.xml', u'filezilla.xml']:
				
				xml_file = os.path.join(path, file)

				if os.path.exists(xml_file):
					tree 		= ET.ElementTree(file=xml_file)
					servers 	= tree.findall('Servers/Server') if tree.findall('Servers/Server') else tree.findall('RecentServers/Server')
					
					for server in servers:
						host 		= server.find('Host')
						port 		= server.find('Port')
						login 		= server.find('User')
						password 	= server.find('Pass')
						
						if host is not None and port is not None and login is not None:
							values = {
										'Host'		: host.text, 
										'Port'		: port.text, 
										'Login'		: login.text,
									}

						if password is not None:
							if 'encoding' in password.attrib and password.attrib['encoding'] == 'base64':
								values['Password'] = base64.b64decode(password.text)
							else:
								values['Password'] = password.text

						pwdFound.append(values)

			return pwdFound
