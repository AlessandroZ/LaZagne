import xml.etree.cElementTree as ET
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config import homes
import os, base64

class Filezilla(ModuleInfo):
	def __init__(self):
		options = {'command': '-f', 'action': 'store_true', 'dest': 'filezilla', 'help': 'filezilla'}
		ModuleInfo.__init__(self, 'filezilla', 'sysadmin', options)

	def run(self, software_name = None):
		pwdFound = []

		# legend = {
		#	  'sitemanager.xml': 'Stores all saved sites server info including password in plaintext',
		#	  'recentservers.xml': 'Stores all recent server info including password in plaintext',
		#	  'filezilla.xml': 'Stores most recent server info including password in plaintext'
		# }

		for xml_file in homes.get(file=[
			os.path.join(d, f)
			for d in ('.filezilla', '.config/filezilla')
			for f in ('sitemanager.xml', 'recentservers.xml', 'filezilla.xml')
		]):
			print_debug('INFO', '%s' % (xml_file))

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
