#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from xml.etree.cElementTree import ElementTree

from lazagne.config import homes
from lazagne.config.module_info import ModuleInfo


class Squirrel(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'squirrel', 'databases')

    def get_paths(self):
        return homes.get(file=os.path.join('.squirrel-sql', 'SQLAliases23.xml'))

    def parse_xml(self, path):
        pwd_found = []
        if os.path.exists(path):
            tree = ElementTree(file=path)
            elements = {'name': 'Name', 'url': 'URL', 'userName': 'Login', 'password': 'Password'}
            for elem in tree.iter('Bean'):
                values = {}
                for e in elem:
                    if e.tag in elements:
                        values[elements[e.tag]] = e.text
                if values:
                    pwd_found.append(values)

        return pwd_found

    def run(self):
        all_passwords = []
        for path in self.get_paths():
            all_passwords += self.parse_xml(path)

        return all_passwords
