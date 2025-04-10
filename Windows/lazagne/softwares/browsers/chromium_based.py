# -*- coding: utf-8 -*-

# Thank you all for the Yandex browser support: 
# - https://github.com/AlessandroZ/LaZagne/issues/483
# Here are great projects: 
# - https://github.com/Goodies365/YandexDecrypt
# - https://github.com/LimerBoy/Soviet-Thief

import base64
import json
import os
import random
import shutil
import sqlite3
import string
import tempfile
import traceback

from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Util.Padding import unpad

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import Win32CryptUnprotectData
from lazagne.softwares.windows.credman import Credman


class ChromiumBased(ModuleInfo):
    def __init__(self, browser_name, paths):
        self.paths = paths if isinstance(paths, list) else [paths]
        self.database_query = 'SELECT origin_url, username_value, password_value FROM logins'
        ModuleInfo.__init__(self, browser_name, 'browsers', winapi_used=True)

    def _get_database_dirs(self):
        """
        Return database directories for all profiles within all paths
        """
        databases = set()
        for path in [p.format(**constant.profile) for p in self.paths]:
            profiles_path = os.path.join(path, u'Local State')
            if os.path.exists(profiles_path):
                master_key = None
                # List all users profile (empty string means current dir, without a profile)
                profiles = {'Default', ''}

                # Automatic join all other additional profiles
                for dirs in os.listdir(path):
                    dirs_path = os.path.join(path, dirs)
                    if os.path.isdir(dirs_path) and dirs.startswith('Profile'):
                        profiles.add(dirs)

                with open(profiles_path, "r", encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                        # Add profiles from json to Default profile. set removes duplicates
                        profiles |= set(data['profile']['info_cache'])
                    except Exception:
                        pass

                with open(profiles_path, "r", encoding="utf-8") as f:
                    try:
                        master_key = base64.b64decode(json.load(f)["os_crypt"]["encrypted_key"])
                        master_key = master_key[5:]  # removing DPAPI
                        master_key = Win32CryptUnprotectData(master_key, is_current_user=constant.is_current_user,
                                                user_dpapi=constant.user_dpapi)
                    except Exception:
                        master_key = None

                # Each profile has its own password database
                for profile in profiles:
                    # Some browsers use names other than "Login Data"
                    # Like YandexBrowser - "Ya Login Data", UC Browser - "UC Login Data.18"
                    try:
                        db_files = os.listdir(os.path.join(path, profile))
                    except Exception:
                        continue
                    for db in db_files:
                        if db.lower() in ['login data', 'ya passman data']:
                            databases.add((os.path.join(path, profile, db), master_key))
        return databases

    def _decrypt_v80(self, buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
            return decrypted_pass
        except:
            pass

    def _yandex_extract_enc_key(self, db_cursor, decrypted_key):
        db_cursor.execute('SELECT value FROM meta WHERE key = \'local_encryptor_data\'')
        local_encryptor = db_cursor.fetchone()

        # Check local encryptor values
        if local_encryptor == None:
            self.debug('[!] Failed to read local encryptor')
            return None

        # Locate encrypted key bytes
        local_encryptor_data = local_encryptor[0]
        index_enc_data = local_encryptor_data.find(b'v10')
        if index_enc_data == -1:
            self.debug('[!] Encrypted key blob not found')
            return None

        # Extract cipher data
        encrypted_key_blob = local_encryptor_data[index_enc_data + 3 : index_enc_data + 3 + 96]
        nonce = encrypted_key_blob[:12]
        ciphertext = encrypted_key_blob[12:-16]
        tag = encrypted_key_blob[-16:]

        # Initialize the AES cipher
        aes_decryptor = AES.new(decrypted_key, AES.MODE_GCM, nonce=nonce)

        # Decrypt the key
        decrypted_data = aes_decryptor.decrypt_and_verify(ciphertext, tag)

        # Check signature
        if int.from_bytes(decrypted_data[:4], 'little') != 0x20120108:
            print('[!] Signature of decrypted local_encryptor_data incorrect')
            return None

        # Got the key :P
        return decrypted_data[4:36]

    def _yandex_decrypt(self, key : bytes, encrypted_data : bytes, nonce : bytes, tag : bytes, aad : bytes) -> str:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        decrypted_data = cipher.decrypt_and_verify(encrypted_data, tag)
        return decrypted_data.decode('utf-8')

    def _export_credentials(self, db_path, is_yandex=False, master_key=None, original_path=None):
        """
        Export credentials from the given database

        :param unicode db_path: database path
        :return: list of credentials
        :rtype: tuple
        """
        credentials = []

        if is_yandex:
            localState = os.path.join(original_path.split('User Data')[0], 'User Data', 'Local State')
            if not os.path.exists(localState):
                return []

            with open(localState, 'rb') as fjson:
                encrypted_key = base64.b64decode(json.load(fjson)['os_crypt']['encrypted_key'])[5:]
                decrypted_key = Win32CryptUnprotectData(encrypted_key, is_current_user=constant.is_current_user,
                                                                        user_dpapi=constant.user_dpapi)

            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
            except Exception:
                self.debug(traceback.format_exc())
                return []

            enc_key = self._yandex_extract_enc_key(cursor, decrypted_key)
            if not enc_key:
                self.info('[!] Failed to extract enc key')
                return []
            self.debug('Encrypted key found: %s' % enc_key)

            # Execute queries
            cursor.execute('SELECT origin_url, username_element, username_value, password_element, password_value, signon_realm FROM logins')
            for url, username_element, username, password_element, password, signon_realm in cursor.fetchall():
                if type(url) == bytes:
                    url = url.decode()
                # Get AAD
                str_to_hash = f'{url}\0{username_element}\0{username}\0{password_element}\0{signon_realm}'
                hash_obj = SHA1.new()
                hash_obj.update(str_to_hash.encode('utf-8'))
                # Decrypt password value
                if len(password) > 0:
                    try:
                        decrypted = self._yandex_decrypt(
                            key=enc_key,
                            encrypted_data=password[12:-16],
                            nonce=password[:12],
                            tag=password[-16:],
                            aad=hash_obj.digest()
                        )
                        credentials.append((url, username, decrypted))
                    except Exception as e: 
                        print(e)

        else:
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute(self.database_query)
            except Exception:
                self.debug(traceback.format_exc())
                return credentials

            for url, login, password in cursor.fetchall():
                try:
                    if type(url) == bytes:
                        url = url.decode()

                    # Decrypt the Password
                    if password and password.startswith(b'v10'):  # chromium > v80
                        if master_key:
                            password = self._decrypt_v80(password, master_key)
                    else:
                        try:
                            password_bytes = Win32CryptUnprotectData(password, is_current_user=constant.is_current_user,
                                                                    user_dpapi=constant.user_dpapi)
                        except AttributeError:
                            try:
                                password_bytes = Win32CryptUnprotectData(password, is_current_user=constant.is_current_user,
                                                                     user_dpapi=constant.user_dpapi)
                            except:
                                password_bytes = None

                        if password_bytes not in [None, False]:
                            password = password_bytes.decode("utf-8")

                    if not url and not login and not password:
                        continue

                    credentials.append((url, login, password))
                except Exception:
                    self.debug(traceback.format_exc())

            conn.close()
        return credentials

    def copy_db(self, database_path):
        """
        Copying db will bypass lock errors
        Using user tempfile will produce an error when impersonating users (Permission denied)
        A public directory should be used if this error occured (e.g C:\\Users\\Public)
        """
        random_name = ''.join([random.choice(string.ascii_lowercase) for i in range(9)])
        root_dir = [
            tempfile.gettempdir(),
            os.environ.get('PUBLIC', None),
            os.environ.get('SystemDrive', None) + '\\',
        ]
        for r in root_dir:
            try:
                temp = os.path.join(r, random_name)
                shutil.copy(database_path, temp)
                self.debug(u'Temporary db copied: {db_path}'.format(db_path=temp))
                return temp
            except Exception:
                self.debug(traceback.format_exc())
        return False

    def clean_file(self, db_path):
        try:
            os.remove(db_path)
        except Exception:
            self.debug(traceback.format_exc())

    def run(self):
        credentials = []
        for database_path, master_key in self._get_database_dirs():
            is_yandex = False if 'yandex' not in database_path.lower() else True

            # Remove Google Chrome false positif
            if database_path.endswith('Login Data-journal'):
                continue

            self.debug('Database found: {db}'.format(db=database_path))

            # Copy database before to query it (bypass lock errors)
            cp_path = self.copy_db(database_path)
            if cp_path:
                try:
                    credentials.extend(self._export_credentials(cp_path, is_yandex, master_key, database_path))
                except Exception:
                    self.debug(traceback.format_exc())
                self.clean_file(cp_path)

        return [{'URL': url, 'Login': login, 'Password': password} for url, login, password in set(credentials)]
