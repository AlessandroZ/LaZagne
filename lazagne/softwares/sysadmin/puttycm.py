# -*- coding: utf-8 -*- 
try: 
    import _winreg as winreg
except ImportError:
    import winreg

from xml.etree.cElementTree import ElementTree

from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import OpenKey, HKEY_CURRENT_USER, string_to_unicode

import os


class Puttycm(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'puttycm', 'sysadmin', registry_used=True)

    def run(self):
        database_path = self.get_default_database()
        if database_path and os.path.exists(database_path):
            return self.parse_xml(database_path)

    def get_default_database(self):
        try:
            key = OpenKey(HKEY_CURRENT_USER, 'Software\\ACS\\PuTTY Connection Manager')
            db = string_to_unicode(winreg.QueryValueEx(key, 'DefaultDatabase')[0])
            winreg.CloseKey(key)
            return db
        except Exception:
            return False

    def parse_xml(self, database_path):
        xml_file = os.path.expanduser(database_path)
        tree = ElementTree(file=xml_file)
        root = tree.getroot()

        pwd_found = []
        elements = ['name', 'protocol', 'host', 'port', 'description', 'login', 'password']
        for connection in root.iter('connection'):
            children = connection.getchildren()
            values = {}
            for child in children:
                for c in child:
                    if str(c.tag) in elements:
                        values[str(c.tag).capitalize()] = str(c.text)

            if values:
                pwd_found.append(values)

        return pwd_found
