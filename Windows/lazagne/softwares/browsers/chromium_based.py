# -*- coding: utf-8 -*- 
import json
import os
import shutil
import sqlite3
import tempfile
import traceback

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import Win32CryptUnprotectData


class ChromiumBased(ModuleInfo):
    def __init__(self, browser_name, paths):
        self.paths = paths if isinstance(paths, list) else [paths]
        self.database_query = 'SELECT action_url, username_value, password_value FROM logins'
        ModuleInfo.__init__(self, browser_name, 'browsers', dpapi_used=True)

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
                password = Win32CryptUnprotectData(password)
                credentials.append((url, login, password))
            except Exception:
                self.debug(traceback.format_exc())

        conn.close()
        return credentials

    def run(self):
        credentials = []
        for database_path in self._get_database_dirs():
            # Copy database before to query it (bypass lock errors)
            try:
                temp = os.path.join(tempfile.gettempdir(), next(tempfile._get_candidate_names())).decode('utf-8')
                shutil.copy(database_path, temp)
                credentials.extend(self._export_credentials(temp))
            except Exception:
                self.debug(traceback.format_exc())

        return [{'URL': url, 'Login': login, 'Password': password} for url, login, password in set(credentials)]


# Name, path or a list of paths
chromium_browsers = [
    (u'7Star', u'{LOCALAPPDATA}\\7Star\\7Star\\User Data'),
    (u'Amigo', u'{LOCALAPPDATA}\\Amigo\\User Data'),
    (u'Brave', u'{APPDATA}\\brave'),
    (u'CentBrowser', u'{LOCALAPPDATA}\\CentBrowser\\User Data'),
    (u'Chedot', u'{LOCALAPPDATA}\\Chedot\\User Data'),
    (u'Chrome Canary', u'{LOCALAPPDATA}\\Google\\Chrome SxS\\User Data'),
    (u'Chromium', u'{LOCALAPPDATA}\\Chromium\\User Data'),
    (u'CocCoc', u'{LOCALAPPDATA}\\CocCoc\\Browser\\User Data'),
    (u'Comodo Dragon', u'{LOCALAPPDATA}\\Comodo\\Dragon\\User Data'),  # Comodo IceDragon is Firefox-based
    (u'Elements Browser', u'{LOCALAPPDATA}\\Elements Browser\\User Data'),
    (u'Epic Privacy Browser', u'{LOCALAPPDATA}\\Epic Privacy Browser\\User Data'),
    (u'Google Chrome', u'{LOCALAPPDATA}\\Google\\Chrome\\User Data'),
    (u'Kometa', u'{LOCALAPPDATA}\\Kometa\\User Data'),
    (u'Opera', u'{APPDATA}\\Opera Software\\Opera Stable'),
    (u'Orbitum', u'{LOCALAPPDATA}\\Orbitum\\User Data'),
    (u'Sputnik', u'{LOCALAPPDATA}\\Sputnik\\Sputnik\\User Data'),
    (u'Torch', u'{LOCALAPPDATA}\\Torch\\User Data'),
    (u'Uran', u'{LOCALAPPDATA}\\uCozMedia\\Uran\\User Data'),
    (u'Vivaldi', u'{LOCALAPPDATA}\\Vivaldi\\User Data'),
    (u'YandexBrowser', u'{LOCALAPPDATA}\\Yandex\\YandexBrowser\\User Data')
]

chromium_browsers = [ChromiumBased(browser_name=name, paths=paths) for name, paths in chromium_browsers]
