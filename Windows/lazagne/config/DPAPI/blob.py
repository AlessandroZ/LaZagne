#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects:
- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""
import codecs
import traceback

from .eater import DataStruct
from . import crypto

from lazagne.config.write_output import print_debug
from lazagne.config.crypto.pyaes.aes import AESModeOfOperationCBC
from lazagne.config.crypto.pyDes import CBC
from lazagne.config.winstructure import char_to_int

AES_BLOCK_SIZE = 16


class DPAPIBlob(DataStruct):
    """Represents a DPAPI blob"""

    def __init__(self, raw=None):
        """
        Constructs a DPAPIBlob. If raw is set, automatically calls parse().
        """
        self.version = None
        self.provider = None
        self.mkguid = None
        self.mkversion = None
        self.flags = None
        self.description = None
        self.cipherAlgo = None
        self.keyLen = 0
        self.hmac = None
        self.strong = None
        self.hashAlgo = None
        self.hashLen = 0
        self.cipherText = None
        self.salt = None
        self.blob = None
        self.sign = None
        self.cleartext = None
        self.decrypted = False
        self.signComputed = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        """Parses the given data. May raise exceptions if incorrect data are
            given. You should not call this function yourself; DataStruct does

            data is a DataStruct object.
            Returns nothing.

        """
        self.version = data.eat("L")
        self.provider = b"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")

        # For HMAC computation
        blobStart = data.ofs

        self.mkversion = data.eat("L")
        self.mkguid = b"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")
        self.flags = data.eat("L")
        self.description = data.eat_length_and_string("L").replace(b"\x00", b"")
        self.cipherAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.keyLen = data.eat("L")
        self.salt = data.eat_length_and_string("L")
        self.strong = data.eat_length_and_string("L")
        self.hashAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.hashLen = data.eat("L")
        self.hmac = data.eat_length_and_string("L")
        self.cipherText = data.eat_length_and_string("L")

        # For HMAC computation
        self.blob = data.raw[blobStart:data.ofs]
        self.sign = data.eat_length_and_string("L")

    def decrypt(self, masterkey, entropy=None, strongPassword=None):
        """Try to decrypt the blob. Returns True/False
        :rtype : bool
        :param masterkey: decrypted masterkey value
        :param entropy: optional entropy for decrypting the blob
        :param strongPassword: optional password for decrypting the blob
        """
        for algo in [crypto.CryptSessionKeyXP, crypto.CryptSessionKeyWin7]:
            try:
                sessionkey = algo(masterkey, self.salt, self.hashAlgo, entropy=entropy, strongPassword=strongPassword)
                key = crypto.CryptDeriveKey(sessionkey, self.cipherAlgo, self.hashAlgo)

                if "AES" in self.cipherAlgo.name:
                    cipher = AESModeOfOperationCBC(key[:int(self.cipherAlgo.keyLength)],
                                                   iv=b"\x00" * int(self.cipherAlgo.ivLength))
                    self.cleartext = b"".join([cipher.decrypt(self.cipherText[i:i + AES_BLOCK_SIZE]) for i in
                                               range(0, len(self.cipherText), AES_BLOCK_SIZE)])
                else:
                    cipher = self.cipherAlgo.module(key, CBC, b"\x00" * self.cipherAlgo.ivLength)
                    self.cleartext = cipher.decrypt(self.cipherText)

                padding = char_to_int(self.cleartext[-1])
                if padding <= self.cipherAlgo.blockSize:
                    self.cleartext = self.cleartext[:-padding]

                # check against provided HMAC
                self.signComputed = algo(masterkey, self.hmac, self.hashAlgo, entropy=entropy, verifBlob=self.blob)
                self.decrypted = self.signComputed == self.sign

                if self.decrypted:
                    return True
            except Exception:
                print_debug('DEBUG', traceback.format_exc())

        self.decrypted = False
        return self.decrypted

    def decrypt_encrypted_blob(self, mkp, entropy_hex=False):
        """
        This function should be called to decrypt a dpapi blob.
        It will find the associcated masterkey used to decrypt the blob.
        :param mkp: masterkey pool object (MasterKeyPool)
        """
        mks = mkp.get_master_keys(self.mkguid)
        if not mks:
            return False, 'Unable to find MK for blob {mk_guid}'.format(mk_guid=self.mkguid)

        entropy = None
        if entropy_hex:
            entropy = codecs.decode(entropy_hex, 'hex')

        for mk in mks:
            if mk.decrypted:
                self.decrypt(mk.get_key(), entropy=entropy)
                if self.decrypted:
                    return True, self.cleartext

        return False, 'Unable to decrypt master key'
