#!/usr/bin/env python
# -*- coding: utf-8 -*-
import crypt
import os

from lazagne.config.module_info import ModuleInfo
from lazagne.config.dico import get_dic


class Shadow(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, 'shadow', 'sysadmin')

    def dictionary_attack(self, user, crypt_pwd):
        dic = get_dic()  # By default 500 most famous passwords are used for the dictionary attack
        dic.insert(0, user)  # Add the user on the list to found weak password (login equal password)

        # Different possible hash type
        # ID  | Method
        # --------------------------------------------------------------------------
        # 1   | MD5
        # 2   | Blowfish (not in mainline glibc; added in some Linux distributions)
        # 5   | SHA-256 (since glibc 2.7)
        # 6   | SHA-512 (since glibc 2.7)

        if '$' not in crypt_pwd:
            # Either malformed or old bcrypt password
            return False

        hash_type = crypt_pwd.split("$")[1]
        hash_algo = {
            '1': 'MD5',
            '2': 'Blowfish',
            '5': 'SHA-256',
            '6': 'SHA-512',
        }

        # For Debug information
        for h_type in hash_algo:
            if h_type == hash_type:
                self.debug('[+] Hash type {algo} detected ...'.format(algo=hash_algo[h_type]))

        real_salt = '${hash_type}${salt}$'.format(hash_type=hash_type, salt=crypt_pwd.split("$")[2])

        # -------------------------- Dictionary attack --------------------------
        self.info('Dictionary Attack on the hash !!! ')
        try:
            for word in dic:
                try:
                    crypt_word = crypt.crypt(word, real_salt)
                    if crypt_word == crypt_pwd:
                        return {
                            'Login': user,
                            'Password': word
                        }
                except Exception as e:
                    pass

        except (KeyboardInterrupt, SystemExit):
            self.debug(u'Dictionary attack interrupted')

        return False

    def run(self):
        shadow_file = '/etc/shadow'
        if os.access(shadow_file, os.R_OK):
            pwd_found = []
            with open(shadow_file, 'r') as shadow_file:
                for line in shadow_file.readlines():
                    user_hash = line.replace('\n', '')
                    line = user_hash.split(':')

                    # Check if a password is defined
                    if not line[1] in ['x', '*', '!', '!!']:
                        user = line[0]
                        crypt_pwd = line[1]

                        # Try dictionary attack
                        result = self.dictionary_attack(user, crypt_pwd)
                        if result:
                            pwd_found.append(result)

                        else:
                            # No clear text password found - save hash
                            pwd_found.append({
                                'Login': user_hash.split(':')[0].replace('\n', ''),
                                'Hash': ':'.join(user_hash.split(':')[1:]),
                            })

                return pwd_found
