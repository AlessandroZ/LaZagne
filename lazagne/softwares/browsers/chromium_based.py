# -*- coding: utf-8 -*- 
import json
import os
import random
import shutil
import sqlite3
import string
import tempfile
import traceback

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import Win32CryptUnprotectData


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
                # List all users profile (empty string means current dir, without a profile)
                profiles = {'Default', ''}
                with open(profiles_path) as f:
                    try:
                        data = json.load(f)
                        # Add profiles from json to Default profile. set removes duplicates
                        profiles |= set(data['profile']['info_cache'])
                    except Exception:
                        pass
                # Each profile has its own password database
                for profile in profiles:
                    # Some browsers use names other than "Login Data"
                    # Like YandexBrowser - "Ya Login Data", UC Browser - "UC Login Data.18"
                    try:
                        db_files = os.listdir(os.path.join(path, profile))
                    except Exception:
                        continue
                    for db in db_files:
                        if u'login data' in db.lower():
                            databases.add(os.path.join(path, profile, db))
        return databases

    def _export_credentials(self, db_path):
        """
        Export credentials from the given database

        :param unicode db_path: database path
        :return: list of credentials
        :rtype: tuple
        """

        credentials = []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute(self.database_query)
        except Exception as e:
            self.debug(str(e))
            return credentials

        for url, login, password in cursor.fetchall():
            try:
                # Decrypt the Password
                password = Win32CryptUnprotectData(password, is_current_user=constant.is_current_user, user_dpapi=constant.user_dpapi)
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
        for database_path in self._get_database_dirs():
            # Remove Google Chrome false positif
            if database_path.endswith('Login Data-journal'):
                continue

            self.debug('Database found: {db}'.format(db=database_path))

            # Copy database before to query it (bypass lock errors)
            path = self.copy_db(database_path)
            if path:
                try:
                    credentials.extend(self._export_credentials(path))
                except Exception:
                    self.debug(traceback.format_exc())
                self.clean_file(path)

        return [{'URL': url, 'Login': login, 'Password': password} for url, login, password in set(credentials)]


# Name, path or a list of paths
chromium_browsers = [
    (u'7Star', u'{LOCALAPPDATA}\\7Star\\7Star\\User Data'),
    (u'amigo', u'{LOCALAPPDATA}\\Amigo\\User Data'),
    (u'brave', u'{APPDATA}\\brave'),
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
