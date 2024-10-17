#!/usr/bin/env python
# -*- coding: utf-8 -*- 
import os
import shutil
import sqlite3
import struct
import traceback

from hashlib import pbkdf2_hmac

# For non-keyring storage
from Crypto.Cipher import AES

from lazagne.config.constant import constant, python_version
from lazagne.config.crypto.pyaes import AESModeOfOperationCBC
from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes


class ChromiumBased(ModuleInfo):
    def __init__(self, browser_name, path):
        self.path = path
        ModuleInfo.__init__(self, browser_name, category='browsers')
        self.enc_config = {
            'iv': b' ' * 16,
            'length': 16,
            'salt': b'saltysalt',
            'iterations': 1,
        }
        self.AES_BLOCK_SIZE = 16

    def get_paths(self):
        for profile_dir in homes.get(directory=self.path):
            try:
                subdirs = os.listdir(profile_dir)
            except Exception:
                continue

            for subdir in subdirs:
                login_data = os.path.join(profile_dir, subdir, 'Login Data')
                if os.path.isfile(login_data):
                    yield login_data

    def remove_padding(self, data):
        """
        Remove PKCS#7 padding
        """
        try:
            nb = struct.unpack('B', data[-1])[0]  # Python 2
        except Exception:
            nb = data[-1]  # Python 3

        try:
            return data[:-nb]
        except Exception:
            self.debug(traceback.format_exc())
            return data

    def _decrypt_v80(self, buff, master_key, AES_mode):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES_mode, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16]  # .decode()  # remove suffix bytes
            return decrypted_pass
        except:
            pass

    def chrome_decrypt(self, encrypted_value, key, init_vector):
        encrypted_value = encrypted_value[3:]
        aes = AESModeOfOperationCBC(key, iv=init_vector)
        cleartxt = b"".join([aes.decrypt(encrypted_value[i:i + self.AES_BLOCK_SIZE])
                             for i in range(0, len(encrypted_value), self.AES_BLOCK_SIZE)])
        return self.remove_padding(cleartxt)

    def get_passwords(self, path):
        try:
            conn = sqlite3.connect(path)
        except Exception:
            return

        cursor = conn.cursor()
        try:
            cursor.execute('SELECT origin_url,username_value,password_value FROM logins')
            for url, user, password in cursor:
                # Password encrypted on the database
                if password[:3] == b'v10' or password[:3] == b'v11':

                    # To decrypt it, Chromium Safe Storage from libsecret module is needed
                    if not constant.chrome_storage:
                        self.info('Password encrypted and Chrome Secret Storage not found')
                        continue

                    else:
                        psswrd = password
                        try:
                            for css in constant.chrome_storage:
                              enc_key = pbkdf2_hmac(
                                  hash_name='sha1', 
                                  password=css, 
                                  salt=self.enc_config['salt'], 
                                  iterations=self.enc_config['iterations'], 
                                  dklen=self.enc_config['length'])

                              try:
                                  password = self.chrome_decrypt(password, key=enc_key, init_vector=self.enc_config['iv'])
                                  password = password if python_version == 2 else password.decode()
                              except UnicodeDecodeError:
                                  password = self._decrypt_v80(password, enc_key, AES.MODE_GCM)
                                  try:
                                      password=password.decode()
                                  except UnicodeDecodeError :
                                      password = self._decrypt_v80(password, enc_key, AES.MODE_CBC)
                              if password:
                                  break
                              else:
                                  password = psswrd

                        except Exception:
                            print(traceback.format_exc())

                if user:
                    yield {
                        'URL': url,
                        'Login': user,
                        'Password': password
                    }
        except Exception:
            print(traceback.format_exc())

        finally:
            cursor.close()
            conn.close()
            os.remove(path)

    def run(self):
        all_passwords = []

        for path in self.get_paths():
            tmp = u'/tmp/chrome.db'
            shutil.copyfile(path, tmp)

            for pw in self.get_passwords(tmp):
                all_passwords.append(pw)

        return all_passwords
