import xml.etree.cElementTree as ET
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
import os, base64

class Filezilla(ModuleInfo):
	def __init__(self):
		options = {'command': '-f', 'action': 'store_true', 'dest': 'filezilla', 'help': 'filezilla'}
		ModuleInfo.__init__(self, 'filezilla', 'sysadmin', options)
	
	def run(self, software_name = None):
		directories = ['~/.filezilla', '~/.config/filezilla']
		for directory in directories:
			directory = os.path.expanduser(directory)
			if os.path.isdir(directory):
				break
		else:
			print_debug('INFO', 'Filezilla not installed.')

		interesting_xml_file = []
		info_xml_file = []
		if os.path.exists(os.path.join(directory, 'sitemanager.xml')):
			interesting_xml_file.append('sitemanager.xml')
			info_xml_file.append('Stores all saved sites server info including password in plaintext')
		
		if os.path.exists(os.path.join(directory, 'recentservers.xml')):
			interesting_xml_file.append('recentservers.xml')
			info_xml_file.append('Stores all recent server info including password in plaintext')
		
		if os.path.exists(os.path.join(directory, 'filezilla.xml')):
			interesting_xml_file.append('filezilla.xml')
			info_xml_file.append('Stores most recent server info including password in plaintext')
		
		if interesting_xml_file != []:
			print_debug('INFO', 'No login and password means anonymous connection')
			
			pwdFound = []
			for i in range(len(interesting_xml_file)):
				print_debug('INFO', '%s: %s' % (interesting_xml_file[i], info_xml_file[i]))
				
				xml_file = os.path.expanduser(directory + os.sep + interesting_xml_file[i])
				
				tree = ET.ElementTree(file=xml_file)
				root = tree.getroot()
				
				servers = root.getchildren()
				for ss in servers:
					server = ss.getchildren()
					
					jump_line = 0
					for s in server:
						s1 = s.getchildren()
						values = {}
						for s11 in s1:
							if s11.tag == 'Host':
								values['Host'] = s11.text
							
							if s11.tag == 'Port':
								values['Port'] = s11.text
							
							if s11.tag == 'User':
								values['Login'] = s11.text
							
							if s11.tag == 'Pass':
								try:
									# if base64 encoding
									if 'encoding' in  s11.attrib:
										if s11.attrib['encoding'] == 'base64':
											values['Password'] = base64.b64decode(s11.text)
									else: 
										values['Password'] = s11.text
								except:
									values['Password'] = s11.text
						
						# write credentials into a text file
						if len(values) != 0:
							pwdFound.append(values)
			return pwdFound
		