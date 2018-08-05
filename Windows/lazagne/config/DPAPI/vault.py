#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
	- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
	- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

from lazagne.config.crypto.pyaes.aes import AESModeOfOperationCBC
from structures import *
from blob import *
import os

AES_BLOCK_SIZE = 16

class Vault():
	def __init__(self, vaults_dir):
		self.vaults_dir = vaults_dir

	def decrypt_vault_attribute(self, vault_attr, key_aes128, key_aes256):
		"""
		Helper to decrypt VAULT attributes.
		"""
		if not vault_attr.size:
			return '', False

		if vault_attr.vault_attr_encrypted.has_iv:
			cipher = AESModeOfOperationCBC(key_aes256, iv=vault_attr.vault_attr_encrypted.encrypted.iv)
			is_attribute_ex = True
		else:
			cipher = AESModeOfOperationCBC(key_aes128)
			is_attribute_ex = False

		data = vault_attr.vault_attr_encrypted.encrypted.data
		decypted = b"".join([cipher.decrypt(data[i:i + AES_BLOCK_SIZE]) for i in range(0, len(data), AES_BLOCK_SIZE)])
		return decypted, is_attribute_ex

	def get_vault_schema(self, guid, base_dir, default_schema):
		"""
		Helper to get the Vault schema to apply on decoded data.
		"""
		vault_schema = default_schema
		schema_file_path = os.path.join(base_dir, guid + '.vsch')
		try:
			with open(schema_file_path, 'rb') as fschema:
				vsch = VAULT_VSCH.parse(fschema.read())
			vault_schema = vault_schemas.get(
				vsch.schema_name.data,
				VAULT_SCHEMA_GENERIC
			)
		except IOError:
			pass
		return vault_schema

	def decrypt(self, mkp):
		""" 
		Decrypt one vault file
		mkp represent the masterkeypool object
		"""
		vpol_filename = os.path.join(self.vaults_dir, 'Policy.vpol')
		if not os.path.exists(vpol_filename):
			return False, u'Policy file not found: {file}'.format(file=vpol_filename)

		with open(vpol_filename, 'rb') as fin:
			vpol = VAULT_POL.parse(fin.read())
		
		# Decrypt blob inside 'Policy.vpol' file
		vpol_blob = DPAPIBlob(DPAPI_BLOB_STRUCT.build(vpol.vpol_store.blob_store.raw))
		ok, vpol_decrypted = vpol_blob.decrypt_encrypted_blob(mkp)
		if not ok:
			return False, u'Unable to decrypt blob. {message}'.format(message=vpol_decrypted)

		vpol_keys 	= VAULT_POL_KEYS.parse(vpol_decrypted)
		key_aes128 	= vpol_keys.vpol_key1.bcrypt_blob.key
		key_aes256 	= vpol_keys.vpol_key2.bcrypt_blob.key
		pwdFound 	= []

		for file in os.listdir(self.vaults_dir):
			if file.lower().endswith('.vcrd'):
				filepath 		= os.path.join(self.vaults_dir, file)
				attributes_data = {}

				with open(filepath, 'rb') as fin:
					vcrd = VAULT_VCRD.parse(fin.read())
				
				current_vault_schema = self.get_vault_schema(
					guid 			= vcrd.schema_guid.upper(),
					base_dir		= self.vaults_dir,
					default_schema	= VAULT_SCHEMA_GENERIC
				)
				for attribute in vcrd.attributes:
					decrypted, is_attribute_ex = self.decrypt_vault_attribute(attribute.pointer, key_aes128, key_aes256)
					if is_attribute_ex:
						schema = current_vault_schema
					else:
						schema = VAULT_SCHEMA_SIMPLE

					attributes_data[attribute.pointer.id] = {
						'data'	: decrypted,
						'schema': schema
					}

				# Parse value found
				for k, v in sorted(attributes_data.iteritems()):
					dataout = v['schema'].parse(v['data'])
					
					# Data retrieved from a well knows schema
					if 'dict' in str(type(dataout)):
						return True, dataout

					else:
						creds_data = {}
						if 'Container' in str(type(dataout)):
							for item in dataout['attribute_item']:
								if item['id'] != 100:
									creds_data[item['id']] = item['item']['data']

							return True, {
								'URL' 		: creds_data['resource'],
								'Login' 	: creds_data['identity'],
								'Password' 	: creds_data['authenticator'],
								'File'		: filepath,
							}

		return False, 'No .vcrd file found. Nothing to decrypt.'
