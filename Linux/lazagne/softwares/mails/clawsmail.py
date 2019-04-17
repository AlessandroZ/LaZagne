#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Thanks to https://github.com/b4n/clawsmail-password-decrypter

import os
import platform
import re
import traceback

from base64 import standard_b64decode as b64decode

from lazagne.config.module_info import ModuleInfo
from lazagne.config.crypto.pyDes import des, ECB, CBC
from lazagne.config.crypto.pyaes import AESModeOfOperationCBC
from lazagne.config.crypto.pbkdf2 import pbkdf2
from lazagne.config import homes

try:
    from ConfigParser import ConfigParser  # Python 2.7
except ImportError:
    from configparser import ConfigParser  # Python 3

CFB = 0  # To implement


class ClawsMail(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'clawsmail', 'mails')

        self.mode = CFB
        if 'FreeBSD' in platform.system():
            self.mode = ECB

        self.passcrypt_key = b'passkey0'
        self.salt = None
        self.pbkdf2_rounds = 0
        self.use_master_passphrase = 0

        self.AES_BLOCK_SIZE = 16
        self.IVLEN = 16
        self.KEYLEN = 32  # AES-256

    def get_paths(self):
        return homes.get(directory=u'.claws-mail')

    def get_clawsrc_conf(self, path):
        p = ConfigParser()
        p.read(os.path.join(path, 'clawsrc'))
        for s in p.sections():
            try:
                self.salt = b64decode(p.get(s, 'master_passphrase_salt'))
                self.pbkdf2_rounds = int(p.get(s, 'master_passphrase_pbkdf2_rounds'))
                self.use_master_passphrase = p.get(s, 'use_master_passphrase')
            except Exception:
                self.debug(traceback.format_exc())

    def pass_decrypt_old(self, p):
        """ Decrypts a password from ClawsMail. => old version """
        if p[0] == '!':  # encrypted password
            buf = b64decode(p[1:])

            """
            If mode is ECB or CBC and the length of the data is wrong, do nothing
            as would the libc algorithms (as they fail early).	Yes, this means the
            password wasn't actually encrypted but only base64-ed.
            """
            if (self.mode in (ECB, CBC)) and ((len(buf) % 8) != 0 or len(buf) > 8192):
                return buf

            c = des(self.passcrypt_key, self.mode, b'\0' * 8)
            return c.decrypt(buf)
        else:
            return p  # raw password

    def pass_decrypt_new(self, encrypted_pwd):
        """ Decrypts a password from ClawsMail. => new version """
        # Everything is explained on the doc / code
        # https://github.com/eworm-de/claws-mail/blob/master/doc/src/password_encryption.txt
        # https://github.com/eworm-de/claws-mail/blob/aca15d9a473bdfdeef4a572b112ff3679d745247/src/password.c#L409

        m = re.match('{(.*),(.*)}(.*)', encrypted_pwd)
        if m:
            # rounds and pbkdf2_rounds should be identical
            mode, rounds, enc_pwd = m.groups()

        masterkey = pbkdf2(self.passcrypt_key, self.salt, int(rounds), self.KEYLEN)

        raw = b64decode(enc_pwd)
        aes = AESModeOfOperationCBC(masterkey, iv='\0' * 16)
        cleartxt = b"".join([aes.decrypt(raw[i:i + self.AES_BLOCK_SIZE]) for i in range(0, len(raw), self.AES_BLOCK_SIZE)])
        plaintext = cleartxt[self.AES_BLOCK_SIZE:]

        try:
            return plaintext.decode()
        except Exception:
            # Password seems not correct
            return plaintext

    def parse_passwordstorerc(self, path, section):
        found = False
        accout_number = section.lower().split(':')[1]
        section_name = 'account:{num}'.format(num=accout_number.strip())
        with open(os.path.join(path, 'passwordstorerc')) as f:
            for line in f.readlines():
                if found:
                    return line.strip()
                if section_name in line:
                    found = True
        return False

    def parse_accountrc(self, path):
        """ Reads passwords from ClawsMail's accountrc file """
        p = ConfigParser()
        p.read(os.path.join(path, 'accountrc'))

        pwd_found = []
        for s in p.sections():
            try:
                address = p.get(s, 'address')
                account = p.get(s, 'account_name')
            except Exception:
                address = '<unknown>'
                account = '<unknown>'

            try:
                # Old version
                password = self.pass_decrypt_old(p.get(s, 'password'))

            except Exception as e:
                # Password not stored on accountrc file
                if not self.salt:
                    self.get_clawsrc_conf(path)

                if self.use_master_passphrase != '0':
                    self.info('Master password used ! ')
                    continue

                encrypted_pwd_line = self.parse_passwordstorerc(path, s)
                if not encrypted_pwd_line:
                    self.info('Password not fount for account {account}'.format(account=s))
                    continue

                _, encrypted_pwd = encrypted_pwd_line.split()
                if encrypted_pwd.startswith('!'):
                    password = self.pass_decrypt_old(encrypted_pwd)
                else:
                    password = self.pass_decrypt_new(encrypted_pwd)

            if password:
                values = {'Login': account, 'URL': address, 'Password': password}
            else:
                values = {'Login': account, 'URL': address}

            pwd_found.append(values)

        return pwd_found

    def run(self):
        all_passwords = []
        for path in self.get_paths():
            all_passwords += self.parse_accountrc(path)

        return all_passwords
