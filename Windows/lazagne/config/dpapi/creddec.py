#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Decrypt Windows Credential files."""

from lazagne.config.dpapi.DPAPI.Core import blob
from lazagne.config.dpapi.DPAPI.Core import masterkey
# from lazagne.config.dpapi.DPAPI.Core import registry
import vaultstruct

def decrypt_blob(mkp, blob):
	"""Helper to decrypt blobs."""
	mks = mkp.getMasterKeys(blob.mkguid)
	if mks:
		for mk in mks:
			if mk.decrypted:
				blob.decrypt(mk.get_key())
				if blob.decrypted:
					break
	else:
		return None, 1

	if blob.decrypted:
		return blob.cleartext, 0
	return None, 2


def decrypt_credential_block(mkp, credential_block):
	"""Helper to decrypt credential block."""
	sblob_raw = ''.join(
			b.raw_data for b in credential_block.CREDENTIAL_DEC_BLOCK_ENC)

	sblob = blob.DPAPIBlob(sblob_raw)

	return decrypt_blob(mkp, sblob)


def helper_dec_err(err_value):
	msg = ''
	if err_value == 1:
		msg = '[-] MasterKey not found for blob.'
	elif err_value == 2:
		msg = '[-] Unable to decrypt blob.'
	else:
		msg = '[-] Decryption error.'
	return msg

def decrypt_user_cred(umkp=None, cred_file=None):

	dec_cred 	= None
	res_err 	= None

	with open(cred_file, 'rb') as fin:

		enc_cred 	= vaultstruct.CREDENTIAL_FILE.parse(fin.read())
		cred_blob 	= blob.DPAPIBlob(enc_cred.data.raw)
		
		if umkp:
			dec_cred, res_err = decrypt_blob(umkp, cred_blob)
		
		if not dec_cred:
			return False, helper_dec_err(res_err)

		cred_dec = vaultstruct.CREDENTIAL_DECRYPTED.parse(dec_cred)
		if cred_dec.header.unk_type == 3:
			return True, {
							'File'     	: '{file}'.format(file=cred_file),
							'Host'   	: '{domain}'.format(domain=cred_dec.main.domain.data), 
							'Login' 	: '{username}'.format(username=cred_dec.main.username.data),
							'Password' 	: '{password}'.format(password=cred_dec.main.password.data),
						}

		# system type
		elif cred_dec.header.unk_type == 2:
			return False, 'System credential type'

		else:
			return False, 'Unknown CREDENTIAL type, please report.\nCreds: {creds}'.format(creds=cred_dec)
	