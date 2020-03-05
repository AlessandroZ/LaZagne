#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

from .blob import DPAPIBlob
from .eater import DataStruct


class CredentialDecryptedHeader(DataStruct):
    """
    Header of the structure returned once the blob has been decrypted
    Header of the CredentialDecrypted class
    """
    def __init__(self, raw=None):
        self.total_size = None
        self.unknown1 = None
        self.unknown2 = None
        self.unknown3 = None
        self.last_update = None
        self.unknown4 = None
        self.unk_type = None
        self.unk_blocks = None
        self.unknown5 = None
        self.unknown6 = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.total_size = data.eat("L")
        self.unknown1 = data.eat("L")
        self.unknown2 = data.eat("L")
        self.unknown3 = data.eat("L")
        self.last_update = data.eat("Q")
        self.unknown4 = data.eat("L")
        self.unk_type = data.eat("L")
        self.unk_blocks = data.eat("L")
        self.unknown5 = data.eat("L")
        self.unknown6 = data.eat("L")


class CredentialDecrypted(DataStruct):
    """
    Structure returned once the blob has been decrypted
    """
    def __init__(self, raw=None):
        self.header_size = None
        self.header = None
        self.domain = None
        self.unk_string1 = None
        self.unk_string2 = None
        self.unk_string3 = None
        self.username = None
        self.password = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.header_size = data.eat("L")
        if self.header_size > 0:
            self.header = CredentialDecryptedHeader()
            self.header.parse(data.eat_sub(self.header_size - 4))
        self.domain = data.eat_length_and_string("L").replace(b"\x00", b"")  # Unicode
        self.unk_string1 = data.eat_length_and_string("L").replace(b"\x00", b"")  # Unicode
        self.unk_string2 = data.eat_length_and_string("L").replace(b"\x00", b"")  # Unicode
        self.unk_string3 = data.eat_length_and_string("L").replace(b"\x00", b"")  # Unicode
        self.username = data.eat_length_and_string("L").replace(b"\x00", b"")  # Unicode
        self.password = data.eat_length_and_string("L").replace(b"\x00", b"")  # Unicode


class CredFile(DataStruct):
    """
    Decrypt Credentials Files stored on ...\\Microsoft\\Credentials\\...
    """
    def __init__(self, raw=None):
        self.unknown1 = None
        self.blob_size = None
        self.unknown2 = None
        self.blob = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.unknown1 = data.eat("L")
        self.blob_size = data.eat("L")
        self.unknown2 = data.eat("L")
        if self.blob_size > 0:
            self.blob = DPAPIBlob()
            self.blob.parse(data.eat_sub(self.blob_size))

    def decrypt(self, mkp, credfile):
        ok, msg = self.blob.decrypt_encrypted_blob(mkp=mkp)
        if ok:
            cred_dec = CredentialDecrypted(msg)
            if cred_dec.header.unk_type in [2, 3]:
                return True, {
                    'File': credfile,
                    'Domain': cred_dec.domain,
                    'Username': cred_dec.username,
                    'Password': cred_dec.password,
                }
            elif cred_dec.header.unk_type == 2:
                return False, 'System credential type'
            else:
                return False, 'Unknown CREDENTIAL type, please report.\nCreds: {creds}'.format(creds=cred_dec)
        else:
            return ok, msg
