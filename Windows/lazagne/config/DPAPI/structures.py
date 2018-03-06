#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
	- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
	- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

from construct import *
import datetime
import struct
import crypto
# import pytz

#===============================================================================
# 					Adapters -  Make the output more human readable
#===============================================================================

class RPC_SIDAdapter(Adapter):
	def _decode(self, sid, context, path):
		s  = ['S-{version}-{idAuth}'.format(version=sid.version, idAuth=struct.unpack('>Q', '\0\0' + sid.idAuth)[0])]
		s += ['%d' % x for x in sid.subAuth]
		return '-'.join(s)

class CryptoAlgoAdapter(Adapter):
	def _decode(self, obj, context, path):
		return crypto.CryptoAlgo(obj)

class GuidAdapter(Adapter):
	def _decode(self, guid, context, path):
		return '{data1:x}-{data2:x}-{data3:x}-{data4}-{data5}'.format(data1=guid.data1, data2=guid.data2, data3=guid.data3, data4=guid.data4.encode('hex')[:4], data5=guid.data4.encode('hex')[4:])

class FileTimeAdapter(Adapter):
	'''Adapted from Rekall Memory Forensics code.'''
	def _decode(self, obj, context, path):
		unix_time = obj / 10000000 - 11644473600
		if unix_time < 0:
			unix_time = 0

		dt = datetime.datetime.utcfromtimestamp(unix_time)
		# dt = dt.replace(tzinfo=pytz.UTC)

		return dt.isoformat()

class UnicodeOrHexAdapter(Adapter):
	'''Helper to pretty print string/hex and remove trailing zeroes.'''
	def _decode(self, obj, context, path):
		try:
			decoded = obj.decode('utf16')
			decoded = decoded.rstrip('\00').encode('utf8')
		except UnicodeDecodeError:
			decoded = obj.encode('hex')
		return decoded

class UnicodeRstripZero(Adapter):
	'''Helper to remove trailing zeroes.'''
	def _decode(self, obj, context, path):
		return obj.rstrip('\x00\x00')

class UnicodeStringActiveSyncAdapter(Adapter):
	'''Helper to pretty print string/hex and remove trailing zeroes.'''
	def _decode(self, obj, context, path):
		try:
			decoded = obj.decode('utf16')
			decoded = decoded.rstrip('\00').encode('utf8')
			if len(obj) <= 8:
				decoded = '{0:s} [hex: {1:s}]'.format(
					decoded, obj.encode('hex'))
		except UnicodeDecodeError:
			decoded = obj.encode('hex')
		return decoded

class VaultSchemaWebPasswordAdapter(Adapter):
	def _decode(self, obj, context, path):
		return {
			'Login'		: obj.identity.data,
			'URL'		: obj.resource.data, 
			'Password'	: obj.authenticator.data,
		}

class VaultSchemaPinAdapter(Adapter):
	def _decode(self, obj, context, path):
		return {
			'SID'		: obj.sid,
			'Resource'	: obj.resource.data, 
			'Password'	: obj.password.data,
			'Pin'		: obj.pin,
		}

class  VaultSchemaActiveSyncAdapter(Adapter):
	def _decode(self, obj, context, path):
		return {
			'Login'		: obj.identity.data,
			'Resource'	: obj.resource.data, 
			'Password'	: obj.authenticator.data,
		}

class VaultSchemaSimpleAdapter(Adapter):
	def _decode(self, obj, context, path):
		dataout = str(bytearray(obj.data))
		return 'hex: {0:s}'.format(dataout.encode('hex'))

#===============================================================================
# 								Common structs.
#===============================================================================

GUID = Struct(
	'data1' / Int32ul,
	'data2' / Int16ul,
	'data3' / Int16ul,
	'data4' / Bytes(8),
)

RPC_SID = Struct(
	'version' 	/ Byte,
	'length' 	/ Byte, 
	'idAuth' 	/ Bytes(6),  # big endian 
	'subAuth' 	/ Array(this.length, Int32ul),
)

UNICODE_STRING = Struct(
	'length' 	/ Int32ul,
	'data'		/ String(this.length, encoding='UTF_16_LE'),
)

UNICODE_STRING_STRIP = Struct(
	'length' 	/ Int32ul,
	'data' 		/ UnicodeRstripZero(String(this.length, encoding='UTF_16_LE'))
)

SIZED_DATA = Struct(
	'size' 	/ Int32ul,
	'data'	/ Bytes(this.size)
)

UNICODE_STRING_HEX = Struct(
	'length' 	/ Int32ul,
	'data'		/ UnicodeOrHexAdapter(Bytes(this.length))
)

UNICODE_STRING_ACTIVESYNC = Struct(
	'length' 	/ Int32ul,
	'data'		/ UnicodeStringActiveSyncAdapter(Bytes(this.length))
)


#===============================================================================
# 								System structs.
#===============================================================================

POL_REVISION = Struct(
	'minor' / Int16ul,
	'major' / Int16ul,
)

SYSTEM_TIME = Struct(
	'time' / FileTimeAdapter(Int64ul),
)

CRED_SYSTEM = Struct(
	'revision' 	/ Int32ul, 
	'machine' 	/ Bytes(20), 
	'user' 		/ Bytes(20), 
)


#===============================================================================
# 								Masterkey structs.
#===============================================================================

# Structure of a masterkey file 
MKFILE = Struct(
	'version' 			/ Int32ul,
	Padding(8),
	'guid' 				/ String(72, encoding='UTF-16'),
	Padding(8),
	'policy' 			/ Int32ul, 							# define if sha-1 or md4 is used
	'masterkeyLen' 		/ Int64ul, 
	'backupkeyLen' 		/ Int64ul,
	'credhistLen' 		/ Int64ul,
	'domainkeyLen' 		/ Int64ul,
	'masterkey' 		/ If(this.masterkeyLen > 0, Struct(
		'version' 		/ Int32ul,
		'iv' 			/ Bytes(16),
		'rounds' 		/ Int32ul,
		'hashAlgo' 		/ CryptoAlgoAdapter(Int32ul),
		'cipherAlgo' 	/ CryptoAlgoAdapter(Int32ul),
		'ciphertext' 	/ Bytes(lambda this: this._.masterkeyLen - this._subcons.version.sizeof() - this._subcons.iv.sizeof() - this._subcons.rounds.sizeof() - this._subcons.hashAlgo.sizeof() - this._subcons.cipherAlgo.sizeof())
	)),
	'backupkey' 		/ If(this.backupkeyLen > 0, Struct(
		'version' 		/ Int32ul,
		'iv' 			/ Bytes(16),
		'rounds' 		/ Int32ul,
		'hashAlgo' 		/ CryptoAlgoAdapter(Int32ul),
		'cipherAlgo' 	/ CryptoAlgoAdapter(Int32ul),
		'ciphertext' 	/ Bytes(lambda this: this._.backupkeyLen - this._subcons.version.sizeof() - this._subcons.iv.sizeof() - this._subcons.rounds.sizeof() - this._subcons.hashAlgo.sizeof() - this._subcons.cipherAlgo.sizeof())
	)),
	'credhist' 			/ If(this.credhistLen > 0, Struct(
		'version' 		/ Int32ul,
		'guid' 			/ GUID,
	)),
	# 'domainkey' 		/ If(this.domainkeyLen > 0, Struct(
	# 	'version' 		/ Int32ul,
	# 	'secretLen' 	/ Int32ul,
	# 	'accesscheckLen'/ Int32ul,
	# 	'guid' 			/ GUID,
	# 	'encrypt_secret'/ Bytes(this.secretLen), 
	# 	'accessCheck'	/ Bytes(this.accesscheckLen),
	# )),
)

#===============================================================================
# 							Cred History File structs.
#===============================================================================

CRED_HIST = Struct(
	Padding(4),
	'revision'		/ Int32ul,
	'hashAlgo'		/ CryptoAlgoAdapter(Int32ul),
	'rounds'		/ Int32ul,
	Padding(4),
	'cipherAlgo'	/ CryptoAlgoAdapter(Int32ul),
	'shaHashLen'	/ Int32ul,
	'ntHashLen'		/ Int32ul,
	'iv'			/ Bytes(16),
	'SID' 			/ RPC_SIDAdapter(RPC_SID),
	# 16 should not be hardcoded
	# crypto.CryptoAlgo(this.cipherAlgo)
	# 16 => self.cipherAlgo.blockSize
	# http://construct.readthedocs.io/en/latest/misc.html#special
	'encrypted'		/ Bytes(this.shaHashLen + this.ntHashLen + ((this.shaHashLen + this.ntHashLen) % 16)), 
	'revision2'		/ Int32ul,
	'guid'			/ GuidAdapter(GUID),
)

# Structure of a Credhist file 
CRED_HIST_FILE = Struct(
	'footmagic' 	/ Int32ul,
	'guid' 			/ GuidAdapter(GUID),
	# Number of credhist should not be hardcoded
	# A way should be found using construct
	'credhist'		/ Optional(Array(1, CRED_HIST)),
)

#===============================================================================
# 								DPAPI Blob
#===============================================================================

# Structure of a Blob 
DPAPI_BLOB = Struct(
	'mkversion' 	/ Int32ul,
	'mkblob' 		/ GUID,
	'flags' 		/ Int32ul, 
	'description' 	/ UNICODE_STRING,
	'cipherAlgo' 	/ Int32ul, 
	'keyLen' 		/ Int32ul, 
	'salt' 			/ SIZED_DATA,
	'strong' 		/ SIZED_DATA,
	'hashAlgo' 		/ Int32ul, 
	'hashLen' 		/ Int32ul, 
	'hmac' 			/ SIZED_DATA,
	'cipherText' 	/ SIZED_DATA,
)

DPAPI_BLOB_STRUCT = Struct(
	'version' 	/ Int32ul,
	# 'provider' 	/ GuidAdapter(GUID),
	'provider' 	/ GUID,
	'blob'		/ DPAPI_BLOB,
	'sign' 		/ SIZED_DATA, 		# For HMAC computation
)

DPAPI_BLOB_STORE = Struct(
	'size'	/ Int32ul,
	'raw'	/ DPAPI_BLOB_STRUCT, 
)


#===============================================================================
# 							Credential Files structs.
#===============================================================================

# CREDENTIALS file structs.

CREDENTIAL_FILE = Struct(
	'unknown1' 	/ Int32ul, 
	'blob_size' / Int32ul, 
	'unknown2' 	/ Int32ul, 
	'blob'		/ Bytes(this.blob_size),
)

CREDENTIAL_DEC_HEADER = Struct(
	'header_size' 	/ Int32ul,
	Embedded(
		Union(	
			this.header_size - 4,
			Embedded(
				Struct(
					'total_size' 	/ Int32ul,
					'unknown1'		/ Int32ul,
					'unknown2'		/ Int32ul,
					'unknown3'		/ Int32ul,
					'last_update'	/ FileTimeAdapter(Int64ul),
					'unknown4'		/ Int32ul,
					'unk_type'		/ Int32ul,
					'unk_blocks'	/ Int32ul,
					'unknown5'		/ Int32ul,
					'unknown6'		/ Int32ul,
				)
			)
		)
	)
)

# Once the blob decrypted, we got a new structure

CREDENTIAL_DEC_MAIN = Struct(
	'domain' 		/ UNICODE_STRING, 
	'unk_string1'	/ UNICODE_STRING, 
	'unk_string2'	/ UNICODE_STRING, 
	'unk_string3'	/ UNICODE_STRING, 
	'username'		/ UNICODE_STRING, 
	'password'		/ UNICODE_STRING, 
)

CREDENTIAL_DEC_BLOCK_ENC = Struct(
	'empty' 		/ Int32ul, 
	'block_name'	/ UNICODE_STRING, 
	'size' 			/ Int32ul, 
	'raw_data'		/ Bytes(this.size)
)

CREDENTIAL_DECRYPTED = Struct(
	'header' 	/ CREDENTIAL_DEC_HEADER, 
	'main'		/ CREDENTIAL_DEC_MAIN, 
	# 'data'		/ If(this.header.unk_type == 2, Array(this.header.unk_blocks, CREDENTIAL_DEC_BLOCK_ENC))
)


#===============================================================================
# 							VAULT POLICY file structs
#===============================================================================

VAULT_POL_STORE = Struct(
	'size' / Int32ul,
	Embedded(
		Union(	
			this.size, 
			Embedded(
				Struct(
					'unknown1'		/ GuidAdapter(GUID),
					'unknown2'		/ GuidAdapter(GUID),
					'blob_store'	/ DPAPI_BLOB_STORE, 
				)
			)
		)
	)
)

VAULT_POL = Struct(
	'version' 		/ Int32ul,
	'guid'			/ GuidAdapter(GUID), 
	'description' 	/ UNICODE_STRING,
	'unknown1' 		/ Int32ul,
	'unknown2' 		/ Int32ul,
	'unknown3' 		/ Int32ul,
	'vpol_store' 	/ VAULT_POL_STORE,
)

# Key Data Blob Magic (KDBM).
BCRYPT_KEY_DATA_BLOB = Struct(
	'dwMagic' 		/ Const(0x4d42444b, Int32ul), 
	'dwVersion' 	/ Int32ul,
	'cbKeyData'		/ Int32ul,
	'key'			/ Bytes(this.cbKeyData)
)

BCRYPT_KEY_STORE = Struct(
	'size' / Int32ul,
	Embedded(
		Union(	
			this.size, 
			Embedded(
				Struct(
						'unknown1'		/ Int32ul,
						'unknown2'		/ Int32ul,
						'bcrypt_blob'	/ BCRYPT_KEY_DATA_BLOB, 
				)
			)
		)
	)
)

VAULT_POL_KEYS = Struct(
	'vpol_key1' / BCRYPT_KEY_STORE, 
	'vpol_key2'	/ BCRYPT_KEY_STORE,
)

#===============================================================================
# 								VAULT file structs 
#===============================================================================

VAULT_ATTRIBUTE_ENCRYPTED = Struct(
	'has_iv' 	/ Byte,
	'encrypted' / IfThenElse(this.has_iv == 1,
		Embedded(
			Struct(	
				'iv_size'	/ Int32ul,
				'iv'		/ Bytes(this.iv_size), 
				'data'		/ Bytes(this._._.size - 1 - 4 - this.iv_size),
			),
		),
		Embedded(
			Struct(	
				'data'		/ Bytes(this._._.size - 1),
			),
		),
	)
)

VAULT_ATTRIBUTE = Struct(
	'id' 					/ Int32ul, 
	'attr_unknown_1' 		/ Int32ul, 
	'attr_unknown_2' 		/ Int32ul, 
	'attr_unknown_3' 		/ Int32ul, 
	# Ok, this is bad, but till now I have not understood how to distinguish
	# the different structs used. Actually the last ATTRIBUTE is different.
	# Usually we have 6 more bytes zeroed, not always aligned: otherwise,
	# if id >= 100, we have 4 more bytes: weird.
	'padding' 				/ Optional(Const('\x00'*6, Bytes(6))),
	'attr_unknown_4'		/ If(this.id >= 100, Int32ul),
	'size' 					/ Int32ul,
	'vault_attr_encrypted'	/ If(this.size > 0, VAULT_ATTRIBUTE_ENCRYPTED),
	'stream_end'			/ Tell,
)

VAULT_ATTRIBUTE_EXTRA = Struct(
	'id' 				/ Int32ul, 
	'attr_unknown_1'	/ Int32ul, 
	'attr_unknown_2'	/ Int32ul, 
	'data'				/ SIZED_DATA,
)

VAULT_ATTRIBUTE_MAP_ENTRY = Struct(
	'id' 						/ Int32ul, 
	'offset'					/ Int32ul, 
	'attr_map_entry_unknown_1'	/ Int32ul,
	'pointer'					/ Pointer(this.offset, VAULT_ATTRIBUTE),
)

VAULT_VCRD = Struct(
	'schema_guid' 			/ GuidAdapter(GUID),
	'vcrd_unknown_1'		/ Int32ul, 
	'last_update' 			/ FileTimeAdapter(Int64ul),
	'vcrd_unknown_2'		/ Int32ul, 
	'vcrd_unknown_3'		/ Int32ul, 
	'description'			/ UNICODE_STRING, 
	'attributes_array_size' / Int32ul,
	# 12 is the size of the VAULT_ATTRIBUTE_MAP_ENTRY structure => VAULT_ATTRIBUTE_MAP_ENTRY.sizeof() fails because of the pointer field
	'attributes_num' 		/ Computed(this.attributes_array_size / 12),
	'attributes' 			/ Array(this.attributes_num,  VAULT_ATTRIBUTE_MAP_ENTRY),
	'extra_entry'			/ Pointer(
								lambda ctx: (ctx.attributes[ctx.attributes_num -1].pointer.stream_end), 
								VAULT_ATTRIBUTE_EXTRA
							),
)

#===============================================================================
# 								VAULT schemas 
#===============================================================================

# Vault file partial parsing

VAULT_VSCH = Struct(
	'version' 				/ Int32ul,
	'schema_guid' 			/ GuidAdapter(GUID), 
	'vault_vsch_unknown_1' 	/ Int32ul,
	'count' 				/ Int32ul,
	'schema_name' 			/ UNICODE_STRING_STRIP, 
)

# Generic Vault Schema

VAULT_ATTRIBUTE_ITEM = Struct(
	"id" / Enum(Int32ul,
		resource 		= 1, 
		identity 		= 2, 
		authenticator 	= 3,
	),
	'item' 	/ Switch(this.id,
		{
			'resource'		: UNICODE_STRING_HEX,
			'identity'		: UNICODE_STRING_HEX,
			'authenticator'	: UNICODE_STRING_HEX,
		},
		default ='generic' / SIZED_DATA
	), 
)

VAULT_SCHEMA_GENERIC = Struct(
	'version' 							/ Int32ul,
	'count' 							/ Int32ul,
	'vault_schema_generic_unknown1'		/ Int32ul,
	'attribute_item'					/ Array(this.count, VAULT_ATTRIBUTE_ITEM) 
)

# Vault Simple Schema

VAULT_SCHEMA_SIMPLE = VaultSchemaSimpleAdapter(
	Struct(
		'data' / GreedyRange(Byte),
	)
)

# PIN Logon Vault Resource Schema

VAULT_SCHEMA_PIN = VaultSchemaPinAdapter(
	Struct(
		'version' 					/ Int32ul,
		'count'						/ Int32ul,
		'vault_schema_pin_unknown1' / Int32ul,
		'id_sid'					/ Int32ul,
		'sid_len'					/ Int32ul, 
		'sid' 						/ Bytes(this.sid_len),
		'id_resource'				/ Int32ul,
		'resource'					/ UNICODE_STRING_STRIP, 
		'id_password'				/ Int32ul,
		'password'					/ UNICODE_STRING_STRIP, 
		'id_pin' 					/ Int32ul,
		'pin' 						/ SIZED_DATA,
	)
)

# Windows Web Password Credential Schema

VAULT_SCHEMA_WEB_PASSWORD = VaultSchemaWebPasswordAdapter(
	Struct(
		'version' 								/ Int32ul,
		'count'									/ Int32ul,
		'vault_schema_web_password_unknown1' 	/ Int32ul,
		'id_identity'							/ Int32ul,
		'identity' 								/ UNICODE_STRING_STRIP, 
		'id_resource'							/ Int32ul,
		'resource' 								/ UNICODE_STRING_STRIP, 
		'id_authenticator'						/ Int32ul,
		'authenticator' 						/ UNICODE_STRING_STRIP, 
	)
)

# Active Sync Credential Schema

VAULT_SCHEMA_ACTIVESYNC = VaultSchemaActiveSyncAdapter(
	Struct(
		'version' 							/ Int32ul,
		'count'								/ Int32ul,
		'vault_schema_activesync_unknown1' 	/ Int32ul,
		'id_identity'						/ Int32ul,
		'identity'							/ UNICODE_STRING_STRIP, 
		'id_resource'						/ Int32ul,
		'resource'							/ UNICODE_STRING_STRIP, 
		'id_authenticator'					/ Int32ul,
		'authenticator'						/ UNICODE_STRING_ACTIVESYNC, 
	)
)

# Vault Schema Dict

vault_schemas = {
	u'ActiveSyncCredentialSchema'		: VAULT_SCHEMA_ACTIVESYNC,
	u'PIN Logon Vault Resource Schema'	: VAULT_SCHEMA_PIN,
	u'Windows Web Password Credential'	: VAULT_SCHEMA_WEB_PASSWORD,
}
