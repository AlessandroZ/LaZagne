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
#
# Credits goes to Benjamin Delphy aka @gentilkiwi and his Mimikatz project:
# vault structs are a mix of my research and his research.
"""Windows Vaults structures."""

import construct
import datetime
# import pytz


# Construct adapters.

class GuidAdapter(construct.Adapter):
	def _decode(self, obj, context):
		return '{:08x}-{:04x}-{:04x}-{:04x}-{:s}'.format(
			construct.ULInt32('foo').parse(obj[0:4]),
			construct.ULInt16('foo').parse(obj[4:6]),
			construct.ULInt16('foo').parse(obj[6:8]),
			construct.UBInt16('foo').parse(obj[8:10]),
			obj[10:16].encode('hex'))


def GUID(name):
	return GuidAdapter(construct.Bytes(name, 16))


class FileTimeAdapter(construct.Adapter):
	'''Adapted from Rekall Memory Forensics code.'''
	def _decode(self, obj, context):
		unix_time = obj / 10000000 - 11644473600
		if unix_time < 0:
			unix_time = 0

		dt = datetime.datetime.utcfromtimestamp(unix_time)
		# dt = dt.replace(tzinfo=pytz.UTC)

		return dt.isoformat()


def FILETIME(name):
	return FileTimeAdapter(construct.ULInt64(name))


# Common structs.

UNICODE_STRING = construct.Struct(
	'UNICODE_STRING',
	construct.ULInt32('length'),
	construct.String('data', lambda ctx: ctx.length, encoding='utf16'))


SIZED_DATA = construct.Struct(
	'SIZED_DATA',
	construct.ULInt32('size'),
	construct.Bytes('data', lambda ctx: ctx.size)
)

# DPAPI structs.

DPAPI_BLOB = construct.Struct(
	'BLOB',
	construct.ULInt32('version'),
	GUID('provider'),
	construct.ULInt32('mk_version'),
	GUID('mk_guid'),
	construct.ULInt32('flags'),
	construct.Rename('description', UNICODE_STRING),
	construct.ULInt32('crypt_alg_id'),
	construct.ULInt32('crypt_alg_len'),
	construct.ULInt32('salt_len'),
	construct.Bytes('salt', lambda ctx: ctx.salt_len),
	construct.ULInt32('unknown1'),
	construct.ULInt32('hash_alg_id'),
	construct.ULInt32('hash_alg_len'),
	construct.ULInt32('hmac_len'),
	construct.Bytes('hmac', lambda ctx: ctx.hmac_len),
	construct.ULInt32('encrypted_len'),
	construct.Bytes('encrypted', lambda ctx: ctx.encrypted_len),
	construct.ULInt32('sign_len'),
	construct.Bytes('sign', lambda ctx: ctx.sign_len)
)

DPAPI_BLOB_STORE = construct.Struct(
	'DPAPI_BLOB_STORE',
	construct.ULInt32('size'),
	construct.Embed(
		construct.Union(
			'',
			construct.Bytes('raw', lambda ctx: ctx.size),
			construct.Rename('blob', DPAPI_BLOB)
		)
	)
)

# VAULT POLICY file structs.

VAULT_POL_STORE = construct.Struct(
	'VAULT_POL_STORE',
	construct.ULInt32('size'),
	construct.Embed(
		construct.Union(
			'',
			construct.Bytes('raw', lambda ctx: ctx.size),
			construct.Embed(
				construct.Struct(
					'',
					GUID('unknown1'),
					GUID('unknown2'),
					construct.Rename('blob_store', DPAPI_BLOB_STORE)
				)
			)
		)
	)
)

VAULT_POL = construct.Struct(
	'VAULT_POL',
	construct.ULInt32('version'),
	GUID('guid'),
	construct.Rename('description', UNICODE_STRING),
	construct.ULInt32('unknown1'),
	construct.ULInt32('unknown2'),
	construct.ULInt32('unknown3'),
	construct.Rename('vpol_store', VAULT_POL_STORE)
)

# Key Data Blob Magic (KDBM).
BCRYPT_KEY_DATA_BLOB_HEADER = construct.Struct(
	'BCRYPT_KEY_DATA_BLOB_HEADER',
	construct.Const(construct.ULInt32('dwMagic'), 0x4d42444b),
	construct.ULInt32('dwVersion'),
	construct.ULInt32('cbKeyData')
)

BCRYPT_KEY_DATA_BLOB = construct.Struct(
	'BCRYPT_KEY_DATA_BLOB',
	construct.Embed(BCRYPT_KEY_DATA_BLOB_HEADER),
	construct.Bytes('key', lambda ctx: ctx.cbKeyData)
)

BCRYPT_KEY_STORE = construct.Struct(
	'BCRYPT_KEY_STORE',
	construct.ULInt32('size'),
	construct.Embed(
		construct.Union(
			'',
			construct.Bytes('raw', lambda ctx: ctx.size),
			construct.Embed(
				construct.Struct(
					'',
					construct.ULInt32('unknown1'),
					construct.ULInt32('unknown2'),
					construct.Rename('bcrypt_blob', BCRYPT_KEY_DATA_BLOB)
				)
			)
		)
	)
)

VAULT_POL_KEYS = construct.Struct(
	'VAULT_POL_KEYS',
	construct.Rename('vpol_key1', BCRYPT_KEY_STORE),
	construct.Rename('vpol_key2', BCRYPT_KEY_STORE)
)

# CREDENTIALS file structs.

CREDENTIAL_FILE = construct.Struct(
	'CREDENTIAL_FILE',
	construct.ULInt32('unknown1'),
	construct.ULInt32('blob_size'),
	construct.ULInt32('unknown2'),
	construct.Union(
		'data',
		construct.Bytes('raw', lambda ctx: ctx._.blob_size),
		construct.Rename('blob', DPAPI_BLOB)
	)
)

CREDENTIAL_DEC_HEADER = construct.Struct(
	'CREDENTIAL_DEC_HEADER',
	construct.ULInt32('header_size'),
	construct.Embed(
		construct.Union(
			'',
			construct.Bytes('raw', lambda ctx: ctx.header_size - 4),
			construct.Embed(
				construct.Struct(
					'',
					construct.ULInt32('total_size'),
					construct.ULInt32('unknown1'),
					construct.ULInt32('unknown2'),
					construct.ULInt32('unknown3'),
					FILETIME('last_update'),
					construct.ULInt32('unknown4'),
					construct.ULInt32('unk_type'),
					construct.ULInt32('unk_blocks'),
					construct.ULInt32('unknown5'),
					construct.ULInt32('unknown6')
				)
			)
		)
	)
)

CREDENTIAL_DEC_MAIN = construct.Struct(
	'CREDENTIAL_DEC_MAIN',
	construct.Rename('domain', UNICODE_STRING),
	construct.Rename('unk_string1', UNICODE_STRING),
	construct.Rename('unk_string2', UNICODE_STRING),
	construct.Rename('unk_string3', UNICODE_STRING),
	construct.Rename('username', UNICODE_STRING),
	construct.Rename('password', UNICODE_STRING)
)

'''
CREDENTIAL_DEC_BLOCK_ENC = construct.Struct(
	'CREDENTIAL_DEC_BLOCK_ENC',
	construct.ULInt32('empty'),
	construct.Rename('block_name', UNICODE_STRING),
	construct.Anchor('position'),
	construct.Padding(lambda ctx: 16 - ctx.position % 16),
	construct.Rename('description', UNICODE_STRING),
	construct.ULInt32('size'),
	construct.Bytes('raw_data', lambda ctx: ctx.size)
)
'''

CREDENTIAL_DEC_BLOCK_ENC = construct.Struct(
	'CREDENTIAL_DEC_BLOCK_ENC',
	construct.ULInt32('empty'),
	construct.Rename('block_name', UNICODE_STRING),
	construct.ULInt32('size'),
	construct.Bytes('raw_data', lambda ctx: ctx.size)
)


CREDENTIAL_DECRYPTED = construct.Struct(
	'CREDENTIAL_DECRYPTED',
	construct.Rename('header', CREDENTIAL_DEC_HEADER),
	construct.Rename('main', CREDENTIAL_DEC_MAIN),
	construct.If(
		lambda ctx: ctx.header.unk_type == 2,
		construct.Array(
			lambda ctx: ctx.header.unk_blocks,
			CREDENTIAL_DEC_BLOCK_ENC
		)
	)
)

# VAULT file structs.

VAULT_ATTRIBUTE_ENCRYPTED = construct.Struct(
	'VAULT_ATTRIBUTE_ENCRYPTED',
	construct.Byte('has_iv'),
	construct.IfThenElse(
		'',
		lambda ctx: ctx.has_iv,
		construct.Embed(
			construct.Struct(
				'encrypted',
				construct.ULInt32('iv_size'),
				construct.Bytes('iv', lambda ctx: ctx.iv_size),
				construct.Bytes(
					'data',
					lambda ctx: ctx.size - 1 - 4 - ctx.iv_size
				)
			)
		),
		construct.Embed(
			construct.Struct(
				'encrypted',     
				construct.Bytes('data', lambda ctx: ctx.size-1)
			)
		)
	)
)

VAULT_ATTRIBUTE = construct.Struct(
	'VAULT_ATTRIBUTE',
	construct.ULInt32('id'),
	construct.ULInt32('attr_unknown_1'),
	construct.ULInt32('attr_unknown_2'),
	construct.ULInt32('attr_unknown_3'),
	# Ok, this is bad, but till now I have not understood how to distinguish
	# the different structs used. Actually the last ATTRIBUTE is different.
	# Usually we have 6 more bytes zeroed, not always aligned: otherwise,
	# if id >= 100, we have 4 more bytes: weird.
	construct.Optional(
		construct.Const(construct.Bytes('padding', 6), '\x00'*6)),
	construct.If(
		lambda ctx: not ctx.padding and ctx.id >= 0x64,
		construct.ULInt32('attr_unknown_4')
	),
	construct.ULInt32('size'),
	construct.If(
		lambda ctx: ctx.size > 0,
		construct.Embed(VAULT_ATTRIBUTE_ENCRYPTED)),
	construct.Anchor('stream_end')
)

VAULT_ATTRIBUTE_EXTRA = construct.Struct(
	'VAULT_ATTRIBUTE_EXTRA',
	construct.ULInt32('id'),
	construct.ULInt32('attr_unknown_1'),
	construct.ULInt32('attr_unknown_2'),
	construct.Embed(SIZED_DATA)
)

VAULT_ATTRIBUTE_MAP_ENTRY = construct.Struct(
	'VAULT_ATTRIBUTE_MAP_ENTRY',
	construct.ULInt32('id'),
	construct.ULInt32('offset'),
	construct.ULInt32('attr_map_entry_unknown_1'),
	construct.Pointer(lambda ctx: ctx.offset, VAULT_ATTRIBUTE)
)

VAULT_VCRD = construct.Struct(
	'VAULT_VCRD',
	GUID('schema_guid'),
	construct.ULInt32('vcrd_unknown_1'),
	FILETIME('last_update'),
	construct.ULInt32('vcrd_unknown_2'),
	construct.ULInt32('vcrd_unknown_3'),
	construct.Rename('description', UNICODE_STRING),
	construct.ULInt32('attributes_array_size'),
	construct.Value(
		'attributes_num',
		lambda ctx: (
			ctx.attributes_array_size / VAULT_ATTRIBUTE_MAP_ENTRY.sizeof())),
	construct.Rename(
		'attributes',
		construct.Array(
			lambda ctx: ctx.attributes_num, VAULT_ATTRIBUTE_MAP_ENTRY)),
	construct.Pointer(
		lambda ctx: (
			ctx.attributes[ctx.attributes_num-1].VAULT_ATTRIBUTE.stream_end),
		construct.Rename('extra_entry', VAULT_ATTRIBUTE_EXTRA))
)
