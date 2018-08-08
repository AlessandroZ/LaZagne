#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import re
import os
import binascii
import hashlib
import struct

from lazagne.config.module_info import ModuleInfo
from lazagne.config.crypto.pyDes import *
from lazagne.config import homes

try:
    from ConfigParser import RawConfigParser  # Python 2.7
except ImportError:
    from configparser import RawConfigParser  # Python 3


class Opera(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'opera', 'browsers')

    def get_paths(self):
        return homes.get(directory=u'.opera')

    def run(self):
        all_passwords = []
        for path in self.get_paths():
            # Check the use of master password
            if not os.path.exists(os.path.join(path, u'operaprefs.ini')):
                self.debug(u'The preference file operaprefs.ini has not been found.')
            else:
                if self.master_password_used(path) == '0':
                    self.debug(u'No master password defined.')
                elif self.master_password_used(path) == '1':
                    self.warning(u'A master password is used.')
                else:
                    self.warning(u'An error occurs, the use of master password is not sure.')

            passwords = self.decipher_old_version(path)

            if passwords:
                all_passwords += self.parse_results(passwords)
            else:
                self.debug(u'The wand.dat seems to be empty')

        return all_passwords

    def decipher_old_version(self, path):
        salt = '837DFC0F8EB3E86973AFFF'

        # Retrieve wand.dat file
        if not os.path.exists(os.path.join(path, u'wand.dat')):
            self.warning(u'wand.dat file has not been found.')
            return

        # Read wand.dat
        with open(os.path.join(path, u'wand.dat', 'rb')) as outfile:
            file = outfile.read()

        passwords = []
        offset = 0

        while offset < len(file):

            offset = file.find('\x08', offset) + 1
            if offset == 0:
                break

            tmp_block_length = offset - 8
            tmp_data_len = offset + 8

            block_length = struct.unpack('!i', file[tmp_block_length: tmp_block_length + 4])[0]
            data_len = struct.unpack('!i', file[tmp_data_len: tmp_data_len + 4])[0]

            binary_salt = binascii.unhexlify(salt)
            des_key = file[offset: offset + 8]
            tmp = binary_salt + des_key

            md5hash1 = hashlib.md5(tmp).digest()
            md5hash2 = hashlib.md5(md5hash1 + tmp).digest()

            key = md5hash1 + md5hash2[0:8]
            iv = md5hash2[8:]

            data = file[offset + 8 + 4: offset + 8 + 4 + data_len]
            des3dec = triple_des(key, CBC, iv)
            try:
                plaintext = des3dec.decrypt(data)
                plaintext = re.sub(r'[^\x20-\x7e]', '', plaintext)
                passwords.append(plaintext)
            except Exception as e:
                self.debug(str(e))
                self.error(u'Failed to decrypt password')

            offset += 8 + 4 + data_len
        return passwords

    def master_password_used(self, path):
        # The init file is not well defined so lines have to be removed before to parse it
        cp = RawConfigParser()
        with open(os.path.join(path, u'operaprefs.ini', 'rb')) as outfile:

            outfile.readline()  # discard first line
            while True:
                try:
                    cp.readfp(outfile)
                    break
                except Exception:
                    outfile.readline()  # discard first line
            try:
                master_pass = cp.get('Security Prefs', 'Use Paranoid Mailpassword')
                return master_pass
            except Exception:
                return False

    def parse_results(self, passwords):

        cpt = 0
        tmp_cpt = 0
        values = {}
        pwd_found = []

        for password in passwords:
            # Date (begin of the sensitive data)
            match = re.search(r'(\d+-\d+-\d+)', password)
            if match:
                values = {}
                cpt = 0
                tmp_cpt = 0

            # After finding 2 urls
            if cpt == 2:
                tmp_cpt += 1
                if tmp_cpt == 2:
                    values['Login'] = password
                elif tmp_cpt == 4:
                    values['Password'] = password
                    pwd_found.append(values)

            # URL
            match = re.search(r'^http', password)
            if match:
                cpt += 1
                if cpt == 1:
                    tmp_url = password
                elif cpt == 2:
                    values['URL'] = tmp_url

        return pwd_found
