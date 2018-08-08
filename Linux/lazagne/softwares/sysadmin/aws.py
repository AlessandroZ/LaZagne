#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes

try:
    from ConfigParser import ConfigParser  # Python 2.7
except ImportError:
    from configparser import ConfigParser  # Python 3


class Aws(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'aws', 'sysadmin')

    def get_paths(self):
        return homes.get(file=os.path.join('.aws', 'credentials'))

    def get_creds(self, path):
        try:
            parser = ConfigParser()
            parser.read(path)
        except Exception:
            return

        for section in parser.sections():
            try:
                key = parser.get(section, 'aws_access_key_id')
                secret = parser.get(section, 'aws_secret_access_key')
                yield section, key, secret
            except Exception:
                continue

    def run(self):
        all_passwords = []
        for path in self.get_paths():
            for section, key, secret in self.get_creds(path):
                all_passwords.append({
                    'ID': key,
                    'KEY': secret,
                    'Service': 'AWS',
                    'Name': section
                })

        return all_passwords
