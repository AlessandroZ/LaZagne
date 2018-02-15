# -*- coding: utf-8 -*- 
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
import json
import os

class Robomongo(ModuleInfo):

	def __init__(self):
		ModuleInfo.__init__(self, 'robomongo', 'databases')
		
		self.paths = [	
						{	
							'directory'	: u'.config/robomongo', 
							'filename'	: u'robomongo.json',
						},
						{
							'directory'	: u'.3T/robo-3t/1.1.1', 
							'filename'	: u'robo3t.json',
						}
					]

	def read_file_content(self, file_path):
		"""
		Read the content of a file

		:param file_path: Path of the file to read.

		:return: File content as string.
		"""
		content = ""
		if os.path.isfile(file_path):
			with open(file_path, 'r') as file_handle:
				content = file_handle.read()

		return content

	def parse_json(self, connection_file_path):
		repos_creds = []
		try:
			with open(connection_file_path) as connection_file:
				connections_infos = json.load(connection_file)
				for connection_infos in connections_infos["connections"]:
					creds = {}
					creds["Name"] = connection_infos["connectionName"]
					creds["Host"] = connection_infos["serverHost"]
					creds["Port"] = connection_infos["serverPort"]
					if bool(connection_infos["credentials"][0]["enabled"]):
						creds["AuthMode"] = "CREDENTIALS"
						creds["DatabaseName"] = connection_infos["credentials"][0]["databaseName"]
						creds["AuthMechanism"] = connection_infos["credentials"][0]["mechanism"]
						creds["Login"] = connection_infos["credentials"][0]["userName"]
						creds["Password"] = connection_infos["credentials"][0]["userPassword"]
					else:
						creds["Host"] = connection_infos["ssh"]["host"]
						creds["Port"] = connection_infos["ssh"]["port"]
						creds["Login"] = connection_infos["ssh"]["userName"]
						if (bool(connection_infos["ssh"]["enabled"]) and
									connection_infos["ssh"]["method"] == "password"):
							creds["AuthMode"] = "SSH_CREDENTIALS"
							creds["Password"] = connection_infos["ssh"]["userPassword"]
						else:
							creds["AuthMode"] = "SSH_PRIVATE_KEY"
							creds["Passphrase"] = connection_infos["ssh"]["passphrase"]
							creds["PrivateKey"] = self.read_file_content(connection_infos["ssh"]["privateKeyFile"])
							creds["PublicKey"] = self.read_file_content(connection_infos["ssh"]["publicKeyFile"])
					repos_creds.append(creds)
		except Exception as e:
			print_debug("ERROR", "Cannot retrieve connections credentials '{error}'".format(error=e))

		return repos_creds 

	def run(self, software_name=None):
		"""
		Extract all connection's credentials.

		:return: List of dict in which one dict contains all information for a connection.
		"""

		for file in self.paths:
			if os.path.exists(os.path.join(constant.profile['USERPROFILE'], file['filename'])):
				return self.parse_json(os.path.join(path, file['filename']))

		for directory in self.paths:
			connection_file_path = os.path.join(constant.profile['USERPROFILE'], directory['directory'], directory['filename'])
			if os.path.exists(connection_file_path):
				return self.parse_json(connection_file_path)
