# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *

from glob import glob
from itertools import cycle

import xml.etree.cElementTree as ET
import os


class PSI(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'psi-im', 'chats')


	def get_profiles_files(self):
		_dirs = (
			u'psi\\profiles\\*\\accounts.xml', 
			u'psi+\\profiles\\*\\accounts.xml',
			)

		for one_dir in _dirs:
			_path = os.path.join(constant.profile['APPDATA'], one_dir)
			accs_files = glob(_path)
			for one_file in accs_files:
				yield one_file


	# Thanks to https://github.com/jose1711/psi-im-decrypt
	def decodePassword(self, password, jid):
		result = ''
		jid = cycle(jid)
		for n1 in xrange(0, len(password), 4):
			x = int(password[n1:n1+4], 16)
			result += chr(x ^ ord(next(jid)))

		return result


	def process_one_file(self, _path):
		root = ET.ElementTree(file=_path).getroot()

		for item in root:
			if item.tag == '{http://psi-im.org/options}accounts':
				for acc in item:
					values = {}

					for x in acc:
						if x.tag == '{http://psi-im.org/options}jid':
							values['Login'] = x.text

						elif x.tag == '{http://psi-im.org/options}password':
							values['Password'] = x.text

					values['Password'] = self.decodePassword(values['Password'], values['Login'])

					if values:
						self.pwdFound.append(values)


	def run(self, software_name = None):
		self.pwdFound = []

		for one_file in self.get_profiles_files():
			self.process_one_file(one_file)

		return self.pwdFound
