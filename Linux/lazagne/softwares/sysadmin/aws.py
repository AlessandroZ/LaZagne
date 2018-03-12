#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from ConfigParser import ConfigParser
from lazagne.config import homes
import os

class Aws(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'aws', 'sysadmin')

	def get_paths(self):
		return homes.get(file=os.path.join('.aws', 'credentials'))

	def get_creds(self, path):
		try:
			parser = ConfigParser()
			parser.read(path)
		except:
			return

		for section in parser.sections():
			try:
				key 	= parser.get(section, 'aws_access_key_id')
				secret 	= parser.get(section, 'aws_secret_access_key')
				yield section, key, secret
			except:
				continue

	def run(self, software_name=None):
		all_passwords = []
		for path in self.get_paths():
			for section, key, secret in self.get_creds(path):
				all_passwords.append({
					'ID': key,
					'KEY': secret,
					'Service': 'AWS',
					'Name': section
				})

		return all_passwords
