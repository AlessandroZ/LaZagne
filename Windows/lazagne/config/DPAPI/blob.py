#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

from .structures import *
import crypto


class DPAPIBlob():

    def __init__(self, dpapiblob):
        self.dpapiblob = DPAPI_BLOB_STRUCT.parse(dpapiblob)
        self.decrypted = False
        self.cleartext = None
        self.blob = self.dpapiblob.blob
        self.blob_not_modified = DPAPI_BLOB.build(self.blob)
        self.blob.hashAlgo = crypto.CryptoAlgo(self.blob.hashAlgo)
        self.blob.cipherAlgo = crypto.CryptoAlgo(self.blob.cipherAlgo)
        self.mkguid = self.guid_to_str(self.blob.mkblob)

    def guid_to_str(self, guid):
        return '{data1:x}-{data2:x}-{data3:x}-{data4}-{data5}'.format(data1=guid.data1,
                                                                      data2=guid.data2,
                                                                      data3=guid.data3,
                                                                      data4=guid.data4.encode('hex')[:4],
                                                                      data5=guid.data4.encode('hex')[4:])

    def decrypt(self, masterkey, entropy=None, strongPassword=None):
        """
        Try to decrypt the blob.
        :param masterkey: decrypted masterkey value
        """
        for algo in [crypto.CryptSessionKeyXP, crypto.CryptSessionKeyWin7]:
            sessionkey = algo(masterkey, self.blob.salt.data, self.blob.hashAlgo, entropy=entropy,
                              strongPassword=strongPassword)
            key = crypto.CryptDeriveKey(sessionkey, self.blob.cipherAlgo, self.blob.hashAlgo)
            cipher = self.blob.cipherAlgo.module.new(
                key[:self.blob.cipherAlgo.keyLength],
                mode=self.blob.cipherAlgo.module.MODE_CBC,
                IV="\x00" * self.blob.cipherAlgo.ivLength
            )
            self.cleartext = cipher.decrypt(self.blob.cipherText.data)
            padding = ord(self.cleartext[-1])

            if padding <= self.blob.cipherAlgo.blockSize:
                self.cleartext = self.cleartext[:-padding]

            # check against provided HMAC
            signComputed = algo(masterkey, self.blob.hmac.data, self.blob.hashAlgo, entropy=entropy,
                                verifBlob=self.blob_not_modified)
            self.decrypted = signComputed == self.dpapiblob.sign.data
            if self.decrypted:
                return True

        self.decrypted = False
        return self.decrypted

    def decrypt_encrypted_blob(self, mkp, entropy_hex=None):
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
            entropy = entropy_hex.decode('hex')

        for mk in mks:
            if mk.decrypted:
                self.decrypt(mk.get_key(), entropy=entropy)
                if self.decrypted:
                    return True, self.cleartext

        return False, 'Unable to decrypt master key'
