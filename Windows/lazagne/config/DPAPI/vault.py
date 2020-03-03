#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
- DPAPICK   : https://bitbucket.org/jmichel/dpapick
- DPAPILAB  : https://github.com/dfirfpi/dpapilab
"""

import codecs
import struct

from .blob import DPAPIBlob
from .eater import DataStruct, Eater
from lazagne.config.crypto.pyaes.aes import AESModeOfOperationCBC
from lazagne.config.winstructure import char_to_int

import os

AES_BLOCK_SIZE = 16

# ===============================================================================
#                           VAULT POLICY file structs
# ===============================================================================


class VaultPolicyKey(DataStruct):
    """
    Structure containing the AES key used to decrypt the vcrd files
    """
    def __init__(self, raw=None):
        # self.size = None
        self.unknown1 = None
        self.unknown2 = None
        self.dwMagic = None
        self.dwVersion = None
        self.cbKeyData = None
        self.key = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        # self.size = data.eat("L")
        self.unknown1 = data.eat("L")
        self.unknown2 = data.eat("L")
        self.dwMagic = data.eat("L")  # Constant: 0x4d42444b
        self.dwVersion = data.eat("L")
        self.cbKeyData = data.eat("L")
        if self.cbKeyData > 0:
            # self.key = data.eat_sub(self.cbKeyData)
            self.key = data.eat(str(self.cbKeyData) + "s")



class VaultPolicyKeys(DataStruct):
    """
    Structure containing two AES keys used to decrypt the vcrd files
    - First key is an AES 128
    - Second key is an AES 256
    """
    def __init__(self, raw=None):
        self.vpol_key1_size = None
        self.vpol_key1 = None
        self.vpol_key2_size = None
        self.vpol_key2 = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.vpol_key1_size = data.eat("L")
        if self.vpol_key1_size > 0:
            self.vpol_key1 = VaultPolicyKey()
            self.vpol_key1.parse(data.eat_sub(self.vpol_key1_size))

        self.vpol_key2_size = data.eat("L")
        if self.vpol_key2_size > 0:
            self.vpol_key2 = VaultPolicyKey()
            self.vpol_key2.parse(data.eat_sub(self.vpol_key2_size))


class VaultPolicy(DataStruct):
    """
    Policy.vpol file is a DPAPI blob with an header containing a textual description
    and a GUID that should match the Vault folder name
    Once the blob is decrypted, we get two AES keys to be used in decrypting the vcrd files.
    """
    def __init__(self, raw=None):
        self.version = None
        self.guid = None
        self.description = None
        self.unknown1 = None
        self.unknown2 = None
        self.unknown3 = None
        # VPOL_STORE
        self.size = None
        self.unknown4 = None
        self.unknown5 = None
        # DPAPI_BLOB_STORE
        self.blob_store_size = None
        self.blob_store_raw = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.guid = b"%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")  # data.eat("16s")
        self.description = data.eat_length_and_string("L").replace(b"\x00", b"")  # Unicode
        self.unknown1 = data.eat("L")
        self.unknown2 = data.eat("L")
        self.unknown3 = data.eat("L")
        # VPOL_STORE
        self.size = data.eat("L")
        self.unknown4 = b"%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")  # data.eat("16s")
        self.unknown5 = b"%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")  # data.eat("16s")
        # DPAPI_BLOB_STORE
        self.blob_store_size = data.eat("L")
        if self.blob_store_size > 0:
            self.blob_store_raw = DPAPIBlob()
            self.blob_store_raw.parse(data.eat_sub(self.blob_store_size))

# ===============================================================================
#                               VAULT file structs
# ===============================================================================


class VaultAttribute(DataStruct):
    """
    This class contains the encrypted data we are looking for (data + iv)
    """
    def __init__(self, raw=None):
        self.id = None
        self.attr_unknown_1 = None
        self.attr_unknown_2 = None
        self.attr_unknown_3 = None
        self.padding = None
        self.attr_unknown_4 = None
        self.size = None
        # VAULT_ATTRIBUTE_ENCRYPTED
        self.has_iv = None
        self.iv_size = None
        self.iv = None
        self.data = None
        self.stream_end = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.id = data.eat("L")
        self.attr_unknown_1 = data.eat("L")
        self.attr_unknown_2 = data.eat("L")
        self.attr_unknown_3 = data.eat("L")
        # self.padding = data.eat("6s")
        if self.id >= 100:
            self.attr_unknown_4 = data.eat("L")
        self.size = data.eat("L")
        if self.size > 0:
            self.has_iv = ord(data.eat("1s"))
            
            if self.has_iv == 1:
                self.iv_size = data.eat("L")
                self.iv = data.eat(str(self.iv_size)+ "s")
                self.data = data.eat(str(self.size - 1 - 4 - self.iv_size) + "s")
            else:
                self.data = data.eat(str(self.size - 1) + "s")


class VaultAttributeMapEntry(DataStruct):
    """
    This class contains a pointer on VaultAttribute structure
    """
    def __init__(self, raw=None):
        self.id = None
        self.offset = None
        self.attr_map_entry_unknown_1 = None
        self.pointer = None
        self.extra_entry = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.id = data.eat("L")
        self.offset = data.eat("L")
        self.attr_map_entry_unknown_1 = data.eat("L")


class VaultVcrd(DataStruct):
    """
    vcrd files contain encrypted attributes encrypted with the previous AES keys which represents the target secret
    """
    def __init__(self, raw=None):
        self.schema_guid = None
        self.vcrd_unknown_1 = None
        self.last_update = None
        self.vcrd_unknown_2 = None
        self.vcrd_unknown_3 = None
        self.description = None
        self.attributes_array_size = None
        self.attributes_num = None
        self.attributes = []
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.schema_guid = b"%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")  # data.eat("16s")
        self.vcrd_unknown_1 = data.eat("L")
        self.last_update = data.eat("Q")
        self.vcrd_unknown_2 = data.eat("L")
        self.vcrd_unknown_3 = data.eat("L")
        self.description = data.eat_length_and_string("L").replace(b"\x00", b"")  # Unicode
        self.attributes_array_size = data.eat("L")
        # 12 is the size of the VAULT_ATTRIBUTE_MAP_ENTRY
        self.attributes_num = self.attributes_array_size // 12
        for i in range(self.attributes_num):
            # 12: size of VaultAttributeMapEntry Structure
            v_map_entry = VaultAttributeMapEntry(data.eat("12s"))
            self.attributes.append(v_map_entry)

# ===============================================================================
#                                VAULT schemas
# ===============================================================================


class VaultVsch(DataStruct):
    """
    Vault Schemas
    Vault file partial parsing
    """
    def __init__(self, raw=None):
        self.version = None
        self.schema_guid = None
        self.vault_vsch_unknown_1 = None
        self.count = None
        self.schema_name = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.schema_guid = b"%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")
        self.vault_vsch_unknown_1 = data.eat("L")
        self.count = data.eat("L")
        self.schema_name = data.eat_length_and_string("L").replace(b"\x00", b"")


class VaultAttributeItem(object):
    def __init__(self, id_, item):
        self.id = id_
        self.item = codecs.encode(item, 'hex')


class VaultSchemaGeneric(DataStruct):
    """
    Generic Vault Schema
    """
    def __init__(self, raw=None):
        self.version = None
        self.count = None
        self.vault_schema_generic_unknown1 = None
        self.attribute_item = []
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.count = data.eat("L")
        self.vault_schema_generic_unknown1 = data.eat("L")
        for i in range(self.count):
            self.attribute_item.append(
                VaultAttributeItem(
                    id_=data.eat("L"),
                    item=data.eat_length_and_string("L").replace(b"\x00", b"")
                )
            )

# Vault Simple Schema

# VAULT_SCHEMA_SIMPLE = VaultSchemaSimpleAdapter(
#     Struct(
#         'data' / GreedyRange(Byte),
#     )
# )


class VaultSchemaPin(DataStruct):
    """
    PIN Logon Vault Resource Schema
    """
    def __init__(self, raw=None):
        self.version = None
        self.count = None
        self.vault_schema_pin_unknown1 = None
        self.id_sid = None
        self.sid_len = None
        self.sid = None
        self.id_resource = None
        self.resource = None
        self.id_password = None
        self.password = None
        self.id_pin = None
        self.pin = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.count = data.eat("L")
        self.vault_schema_pin_unknown1 = data.eat("L")
        self.id_sid = data.eat("L")
        self.sid_len = data.eat("L")
        if self.sid_len > 0:
            self.sid = data.eat_sub(self.sid_len)
        self.id_resource = data.eat("L")
        self.resource = data.eat_length_and_string("L").replace(b"\x00", b"")
        self.id_password = data.eat("L")
        self.authenticator = data.eat_length_and_string("L").replace(b"\x00", b"")  # Password
        self.id_pin = data.eat("L")
        self.pin = data.eat_length_and_string("L")


class VaultSchemaWebPassword(DataStruct):
    """
    Windows Web Password Credential Schema
    """
    def __init__(self, raw=None):
        self.version = None
        self.count = None
        self.vault_schema_web_password_unknown1 = None
        self.id_identity = None
        self.identity = None
        self.id_resource = None
        self.resource = None
        self.id_authenticator = None
        self.authenticator = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.count = data.eat("L")
        self.vault_schema_web_password_unknown1 = data.eat("L")
        self.id_identity = data.eat("L")
        self.identity = data.eat_length_and_string("L").replace(b"\x00", b"")
        self.id_resource = data.eat("L")
        self.resource = data.eat_length_and_string("L").replace(b"\x00", b"")
        self.id_authenticator = data.eat("L")
        self.authenticator = data.eat_length_and_string("L").replace(b"\x00", b"")


class VaultSchemaActiveSync(DataStruct):
    """
    Active Sync Credential Schema
    """
    def __init__(self, raw=None):
        self.version = None
        self.count = None
        self.vault_schema_activesync_unknown1 = None
        self.id_identity = None
        self.identity = None
        self.id_resource = None
        self.resource = None
        self.id_authenticator = None
        self.authenticator = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.count = data.eat("L")
        self.vault_schema_activesync_unknown1 = data.eat("L")
        self.id_identity = data.eat("L")
        self.identity = data.eat_length_and_string("L").replace(b"\x00", b"")
        self.id_resource = data.eat("L")
        self.resource = data.eat_length_and_string("L").replace(b"\x00", b"")
        self.id_authenticator = data.eat("L")
        self.authenticator = codecs.encode(data.eat_length_and_string("L").replace(b"\x00", b""), 'hex')


# Vault Schema Dict
vault_schemas = {
    b'ActiveSyncCredentialSchema'       : VaultSchemaActiveSync,
    b'PIN Logon Vault Resource Schema'  : VaultSchemaPin,
    b'Windows Web Password Credential'  : VaultSchemaWebPassword,
}


# ===============================================================================
#                               VAULT Main Function
# ===============================================================================


class Vault(object):
    """
    Contains all process to decrypt Vault files
    """
    def __init__(self, vaults_dir):
        self.vaults_dir = vaults_dir

    def decrypt_vault_attribute(self, vault_attr, key_aes128, key_aes256):
        """
        Helper to decrypt VAULT attributes.
        """
        if not vault_attr.size:
            return b'', False

        if vault_attr.has_iv:  
            cipher = AESModeOfOperationCBC(key_aes256, iv=vault_attr.iv)
            is_attribute_ex = True
        else:
            cipher = AESModeOfOperationCBC(key_aes128)
            is_attribute_ex = False

        data = vault_attr.data
        decypted = b"".join([cipher.decrypt(data[i:i + AES_BLOCK_SIZE]) for i in range(0, len(data), AES_BLOCK_SIZE)])
        return decypted, is_attribute_ex

    def get_vault_schema(self, guid, base_dir, default_schema):
        """
        Helper to get the Vault schema to apply on decoded data.
        """
        vault_schema = default_schema
        schema_file_path = os.path.join(base_dir.encode(), guid + b'.vsch')
        try:
            with open(schema_file_path, 'rb') as fschema:
                vsch = VaultVsch(fschema.read())
            vault_schema = vault_schemas.get(
                vsch.schema_name,
                VaultSchemaGeneric
            )
        except IOError:
            pass
        return vault_schema

    def decrypt(self, mkp):
        """
        Decrypt one vault file
        mkp represent the masterkeypool object
        Very well explained here: http://blog.digital-forensics.it/2016/01/windows-revaulting.html
        """
        vpol_filename = os.path.join(self.vaults_dir, 'Policy.vpol')
        if not os.path.exists(vpol_filename):
            return False, u'Policy file not found: {file}'.format(file=vpol_filename)

        with open(vpol_filename, 'rb') as fin:
            vpol = VaultPolicy(fin.read())

        ok, vpol_decrypted = vpol.blob_store_raw.decrypt_encrypted_blob(mkp)
        if not ok:
            return False, u'Unable to decrypt blob. {message}'.format(message=vpol_decrypted)

        vpol_keys = VaultPolicyKeys(vpol_decrypted)
        key_aes128 = vpol_keys.vpol_key1.key
        key_aes256 = vpol_keys.vpol_key2.key

        for file in os.listdir(self.vaults_dir):
            if file.lower().endswith('.vcrd'):
                filepath = os.path.join(self.vaults_dir, file)
                attributes_data = {}

                with open(filepath, 'rb') as fin:
                    vcrd = VaultVcrd(fin.read())

                    current_vault_schema = self.get_vault_schema(
                        guid=vcrd.schema_guid.upper(),
                        base_dir=self.vaults_dir,
                        default_schema=VaultSchemaGeneric
                    )
                    for attribute in vcrd.attributes:
                        fin.seek(attribute.offset)

                        v_attribute = VaultAttribute(fin.read())
                        # print('-id: ', v_attribute.id)
                        # print('-size: ', v_attribute.size)
                        # print('-data: ', repr(v_attribute.data))
                        # print('-has_iv: ', v_attribute.has_iv)
                        # print('-iv: ', repr(v_attribute.iv))

                        decrypted, is_attribute_ex = self.decrypt_vault_attribute(v_attribute, key_aes128, key_aes256)
                        if is_attribute_ex:
                            schema = current_vault_schema
                        else:
                            # schema = VAULT_SCHEMA_SIMPLE
                            continue

                        attributes_data[attribute.id] = {
                            'data': decrypted,
                            'schema': schema
                        }

                    # Parse value found
                    for k, v in sorted(attributes_data.items()):
                        # Parse decrypted data depending on its schema
                        dataout = v['schema'](v['data'])

                        if dataout: 
                            return True, {
                                    'URL': dataout.resource,
                                    'Login': dataout.identity,
                                    'Password': dataout.authenticator,
                                    'File': filepath,
                                }

        return False, 'No .vcrd file found. Nothing to decrypt.'