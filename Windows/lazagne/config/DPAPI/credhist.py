#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

import struct
import hashlib

from . import crypto
from .eater import DataStruct


class RPC_SID(DataStruct):
    """
    Represents a RPC_SID structure. See MSDN for documentation
    """
    def __init__(self, raw=None):
        self.version = None
        self.idAuth = None
        self.subAuth = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("B")
        n = data.eat("B")
        self.idAuth = struct.unpack(">Q", b"\0\0" + data.eat("6s"))[0]
        self.subAuth = data.eat("%dL" % n)

    def __str__(self):
        s = ["S-%d-%d" % (self.version, self.idAuth)]
        s += ["%d" % x for x in self.subAuth]
        return "-".join(s)


class CredhistEntry(DataStruct):

    def __init__(self, raw=None):
        self.pwdhash = None
        self.hmac = None
        self.revision = None
        self.hashAlgo = None
        self.rounds = None
        self.cipherAlgo = None
        self.shaHashLen = None
        self.ntHashLen = None
        self.iv = None
        self.userSID = None
        self.encrypted = None
        self.revision2 = None
        self.guid = None
        self.ntlm = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.revision = data.eat("L")
        self.hashAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.rounds = data.eat("L")
        data.eat("L")
        self.cipherAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.shaHashLen = data.eat("L")
        self.ntHashLen = data.eat("L")
        self.iv = data.eat("16s")

        self.userSID = RPC_SID()
        self.userSID.parse(data)

        n = self.shaHashLen + self.ntHashLen
        n += -n % self.cipherAlgo.blockSize
        self.encrypted = data.eat_string(n)

        self.revision2 = data.eat("L")
        self.guid = b"%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")

    def decrypt_with_hash(self, pwdhash):
        """
        Decrypts this credhist entry with the given user's password hash.
        Simply computes the encryption key with the given hash
        then calls self.decrypt_with_key() to finish the decryption.
        """
        self.decrypt_with_key(crypto.derivePwdHash(pwdhash, str(self.userSID)))

    def decrypt_with_key(self, enckey):
        """
        Decrypts this credhist entry using the given encryption key.
        """
        cleartxt = crypto.dataDecrypt(self.cipherAlgo, self.hashAlgo, self.encrypted, enckey,
                                      self.iv, self.rounds)
        self.pwdhash = cleartxt[:self.shaHashLen]
        self.ntlm = cleartxt[self.shaHashLen:self.shaHashLen + self.ntHashLen].rstrip(b"\x00")
        if len(self.ntlm) != 16:
            self.ntlm = None


class CredHistFile(DataStruct):

    def __init__(self, raw=None):
        self.entries_list = []
        self.entries = {}
        self.valid = False
        self.footmagic = None
        self.curr_guid = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        while True:
            l = data.pop("L")
            if l == 0:
                break
            self.addEntry(data.pop_string(l - 4))

        self.footmagic = data.eat("L")
        self.curr_guid = b"%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")

    def addEntry(self, blob):
        """
        Creates a CredhistEntry object with blob then adds it to the store
        """
        x = CredhistEntry(blob)
        self.entries[x.guid] = x
        self.entries_list.append(x)

    def decrypt_with_hash(self, pwdhash):
        """
        Try to decrypt each entry with the given hash
        """

        if self.valid:
            return

        for entry in self.entries_list:
            entry.decrypt_with_hash(pwdhash)

    def decrypt_with_password(self, password):
        """
        Decrypts this credhist entry with the given user's password.
        Simply computes the password hash then calls self.decrypt_with_hash()
        """
        self.decrypt_with_hash(hashlib.sha1(password.encode("UTF-16LE")).digest())
