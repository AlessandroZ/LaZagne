#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This code has been taken from https://github.com/maaaaz/rclonedeobscure
# All credits to maaaaz

from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes

import base64
import json
import os

try:
    from ConfigParser import RawConfigParser  # Python 2.7
except ImportError:
    from configparser import RawConfigParser  # Python 3

from Crypto.Cipher import AES


class Rclone(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'rclone', 'sysadmin')
        # -- https://github.com/rclone/rclone/blob/master/fs/config/obscure/obscure.go
        self.secret_key = b"\x9c\x93\x5b\x48\x73\x0a\x55\x4d\x6b\xfd\x7c\x63\xc8\x86\xa9\x2b\xd3\x90\x19\x8e\xb8\x12\x8a\xfb\xf4\xde\x16\x2b\x8b\x95\xf6\x38"

    def get_paths(self):
        return homes.get(file=os.path.join('.config', 'rclone', 'rclone.conf'))

    def base64_urlsafedecode(self, string):
        '''
        Adds back in the required padding before decoding.
        https://gist.github.com/cameronmaske/f520903ade824e4c30ab
        '''
        padding = 4 - (len(string) % 4)
        string = string + ("=" * padding)
        return base64.urlsafe_b64decode(string)

    def aes_ctr_decrypt(self, encrypted_password, iv):
        '''
        Do not forget to set an empty nonce
        https://stackoverflow.com/questions/56217725/openssh-opensshportable-which-key-should-i-extract-from-memory
        '''
        crypter = AES.new(key=self.secret_key, mode=AES.MODE_CTR, initial_value=iv, nonce=b'')
        decrypted_password = crypter.decrypt(encrypted_password)
        
        return decrypted_password.decode('utf-8')

    def deobscure(self, obscured):
        encrypted_password = self.base64_urlsafedecode(obscured)
        buf = encrypted_password[AES.block_size:]
        iv = encrypted_password[:AES.block_size]
        return self.aes_ctr_decrypt(buf, iv)

    def run(self):
        pwd_found = []
        for path in self.get_paths():
            cp = RawConfigParser()
            cp.read(path)
            for section in cp.sections():
                values = {
                    "Name": section
                }
                for element in cp.options(section): 
                    if 'pass' in element.lower(): 
                        passwd = self.deobscure(cp.get(section, element))
                        values[element.replace('pass', 'Password')] = passwd
                    else: 
                        values[element.capitalize()] = cp.get(section, element)

                pwd_found.append(values)

        return pwd_found
