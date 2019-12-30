#!/usr/bin/python
# -*- coding: utf-8 -*- 
import codecs
import os

from lazagne.config.DPAPI.masterkey import MasterKeyPool
from lazagne.config.DPAPI.credfile import CredFile
from lazagne.config.DPAPI.vault import Vault
from lazagne.config.DPAPI.blob import DPAPIBlob
from lazagne.config.write_output import print_debug
from lazagne.config.constant import constant
from lazagne.softwares.windows.lsa_secrets import LSASecrets


def are_masterkeys_retrieved():
    """
    Before running modules using DPAPI, we have to retrieve masterkeys
    otherwise, we do not realize these checks
    """
    current_user = constant.username
    if constant.pypykatz_result.get(current_user, None):
        password = constant.pypykatz_result[current_user].get('Password', None)
        pwdhash = constant.pypykatz_result[current_user].get('Shahash', None)

        # Create one DPAPI object by user
        constant.user_dpapi = UserDpapi(password=password, pwdhash=pwdhash)

    if not constant.user_dpapi or not constant.user_dpapi.unlocked:
        # constant.user_password represents the password entered manually by the user
        constant.user_dpapi = UserDpapi(password=constant.user_password)

        # Add username to check username equals passwords
        constant.user_dpapi.check_credentials([constant.username] + constant.password_found)

    # Return True if at least one masterkey has been decrypted
    return constant.user_dpapi.unlocked


def manage_response(ok, msg):
    if ok:
        return msg
    else:
        print_debug('DEBUG', u'{msg}'.format(msg=msg))
        return False


class UserDpapi(object):
    """
    User class for DPAPI functions
    """

    def __init__(self, password=None, pwdhash=None):
        self.sid = None
        self.umkp = None
        self.unlocked = False

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
                        for ok, r in self.umkp.try_credential(sid=self.sid, password=password):
                            if ok:
                                self.unlocked = True
                                print_debug('OK', r)
                            else:
                                print_debug('ERROR', r)

                    elif pwdhash:
                        for ok, r in self.umkp.try_credential_hash(self.sid, pwdhash=codecs.decode(pwdhash, 'hex')):
                            if ok:
                                self.unlocked = True
                                print_debug('OK', r)
                            else:
                                print_debug('ERROR', r)

    def check_credentials(self, passwords):
        if self.umkp:
            for password in passwords:
                for ok, r in self.umkp.try_credential(sid=self.sid, password=password):
                    if ok:
                        self.unlocked = True
                        print_debug('OK', r)
                    else:
                        print_debug('ERROR', r)

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
            with open(credfile, 'rb') as f:
                c = CredFile(f.read())
            ok, msg = c.decrypt(self.umkp, credfile)
            return manage_response(ok, msg)

    def decrypt_vault(self, vaults_dir):
        """
        Decrypt Vault Files
        """
        if self.umkp:
            v = Vault(vaults_dir=vaults_dir)
            ok, msg = v.decrypt(mkp=self.umkp)
            return manage_response(ok, msg)

    def decrypt_encrypted_blob(self, ciphered, entropy_hex=False):
        """
        Decrypt encrypted blob
        """
        if self.umkp:
            blob = DPAPIBlob(ciphered)
            ok, msg = blob.decrypt_encrypted_blob(mkp=self.umkp, entropy_hex=entropy_hex)
            return manage_response(ok, msg)

    def get_dpapi_hash(self, context='local'):
        """
        Retrieve DPAPI hash to bruteforce it using john or hashcat.
        """
        if self.umkp:
            return self.umkp.get_dpapi_hash(sid=self.sid, context=context)

    def get_cleartext_password(self):
        """
        Retrieve cleartext password associated to the preferred user maskterkey.
        This password should represent the windows user password.
        """
        if self.umkp:
            return self.umkp.get_cleartext_password()


class SystemDpapi(object):
    """
    System class for DPAPI functions
    Need to have high privilege
    """

    def __init__(self):
        self.smkp = None
        self.unlocked = False

        if not constant.lsa_secrets:
            # Retrieve LSA secrets
            LSASecrets().run()

        if constant.lsa_secrets:
            masterkeydir = u'C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User'
            if os.path.exists(masterkeydir):
                self.smkp = MasterKeyPool()
                self.smkp.load_directory(masterkeydir)
                self.smkp.add_system_credential(constant.lsa_secrets[b'DPAPI_SYSTEM'])
                for ok, r in self.smkp.try_system_credential():
                    if ok:
                        print_debug('OK', r)
                        self.unlocked = True
                    else:
                        print_debug('ERROR', r)

    def decrypt_wifi_blob(self, key_material):
        """
        Decrypt wifi password
        """
        if self.smkp:
            blob = DPAPIBlob(codecs.decode(key_material, 'hex'))
            ok, msg = blob.decrypt_encrypted_blob(mkp=self.smkp)
            return manage_response(ok, msg)
