#!/usr/bin/python
# -*- coding: utf-8 -*- 

from lazagne.config.DPAPI.masterkey import MasterKeyPool
from lazagne.config.DPAPI.credfile import CredFile
from lazagne.config.DPAPI.vault import Vault
from lazagne.config.DPAPI.blob import DPAPIBlob

from lazagne.config.write_output import print_debug
from lazagne.config.constant import constant
from lazagne.softwares.windows.lsa_secrets import LSASecrets

import os


def manage_response(ok, msg):
    if ok:
        return msg
    else:
        print_debug('DEBUG', u'{msg}'.format(msg=msg))
        return False


class Decrypt_DPAPI():
    def __init__(self, password=None, pwdhash=None):
        self.sid = None
        self.umkp = None

        protect_folder = os.path.join(constant.profile['APPDATA'], u'Microsoft', u'Protect')
        credhist_file = os.path.join(constant.profile['APPDATA'], u'Microsoft', u'Protect', u'CREDHIST')

        if os.path.exists(protect_folder):
            for folder in os.listdir(protect_folder):
                if folder.startswith('S-'):
                    self.sid = folder
                    break

            if self.sid:
                masterkeydir = os.path.join(protect_folder, self.sid)
                if os.path.exists(masterkeydir):
                    self.umkp = MasterKeyPool()
                    self.umkp.load_directory(masterkeydir)
                    self.umkp.add_credhist_file(sid=self.sid, credfile=credhist_file)

                    if password:
                        for r in self.umkp.try_credential(sid=self.sid, password=password):
                            print_debug('INFO', r)

                    elif pwdhash:
                        for r in self.umkp.try_credential_hash(self.sid, pwdhash=pwdhash.decode('hex')):
                            print_debug('INFO', r)

    def check_credentials(self, passwords):
        if self.umkp:
            for password in passwords:
                for r in self.umkp.try_credential(sid=self.sid, password=password):
                    print_debug('INFO', r)

    def decrypt_blob(self, dpapi_blob):
        """
        Decrypt DPAPI Blob
        """
        if self.umkp:
            blob = DPAPIBlob(dpapi_blob)
            ok, msg = blob.decrypt_encrypted_blob(mkp=self.umkp)
            return manage_response(ok, msg)

    def decrypt_cred(self, credfile):
        """
        Decrypt Credential Files
        """
        if self.umkp:
            c = CredFile(credfile)
            ok, msg = c.decrypt(self.umkp)
            return manage_response(ok, msg)

    def decrypt_vault(self, vaults_dir):
        """
        Decrypt Vault Files
        """
        if self.umkp:
            v = Vault(vaults_dir=vaults_dir)
            ok, msg = v.decrypt(mkp=self.umkp)
            return manage_response(ok, msg)

    def get_dpapi_hash(self, context='local'):
        """
        Retrieve DPAPI hash to bruteforce it using john or hashcat.
        """
        if self.umkp:
            return self.umkp.get_dpapi_hash(sid=self.sid)

    def get_cleartext_password(self):
        """
        Retrieve cleartext password associated to the preferred user maskterkey.
        This password should represent the windows user password.
        """
        if self.umkp:
            return self.umkp.get_cleartext_password()


class SYSTEM_DPAPI():
    # Need admin priv
    def __init__(self):
        self.smkp = None

        if not constant.lsa_secrets:
            # Retrieve LSA secrets
            LSASecrets().run()

        if constant.lsa_secrets:
            masterkeydir = u'C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User'
            if os.path.exists(masterkeydir):
                self.smkp = MasterKeyPool()
                self.smkp.load_directory(masterkeydir)
                self.smkp.add_system_credential(constant.lsa_secrets['DPAPI_SYSTEM'])
                for ok, r in self.smkp.try_system_credential():
                    if ok:
                        print_debug('OK', r)
                    else:
                        print_debug('ERROR', r)

    def decrypt_wifi_blob(self, key_material):
        """
        Decrypt wifi password
        """
        if self.smkp:
            blob = DPAPIBlob(key_material.decode('hex'))
            ok, msg = blob.decrypt_encrypted_blob(mkp=self.smkp)
            return manage_response(ok, msg)
