#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

import crypto
from .structures import *
from .masterkey import *

import hashlib


class CredhistEntry():

    def __init__(self, credhist):
        self.ntlm = None
        self.pwdhash = None
        self.credhist = credhist

    def decrypt_with_hash(self, pwdhash):
        """
        Decrypts this credhist entry with the given user's password hash.
        Simply computes the encryption key with the given hash then calls self.decrypt_with_key() to finish the decryption.
        """
        self.decrypt_with_key(crypto.derivePwdHash(pwdhash, self.credhist.SID))

    def decrypt_with_key(self, enckey):
        """
        Decrypts this credhist entry using the given encryption key.
        """
        cleartxt = crypto.dataDecrypt(self.credhist.cipherAlgo, self.credhist.hashAlgo, self.credhist.encrypted, enckey,
                                      self.credhist.iv, self.credhist.rounds)
        self.pwdhash = cleartxt[:self.credhist.shaHashLen]
        self.ntlm = cleartxt[self.credhist.shaHashLen:self.credhist.shaHashLen + self.credhist.ntHashLen].rstrip("\x00")
        if len(self.ntlm) != 16:
            self.ntlm = None


class CredHistFile():
    def __init__(self, credhist):
        self.credhistfile = CRED_HIST_FILE.parse(open(credhist, 'rb').read())
        self.entries_list = []
        self.valid = False

        # credhist is an optional field
        if self.credhistfile.credhist:
            for cred in self.credhistfile.credhist:
                c = CredhistEntry(cred)
                self.entries_list.append(c)

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
