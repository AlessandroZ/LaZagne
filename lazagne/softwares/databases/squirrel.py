# -*- coding: utf-8 -*- 
import os
from xml.etree.cElementTree import ElementTree

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo


class Squirrel(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, name='squirrel', category='databases')

    def run(self):
        path = os.path.join(constant.profile['USERPROFILE'], u'.squirrel-sql', u'SQLAliases23.xml')
        if os.path.exists(path):
            tree = ElementTree(file=path)
            pwd_found = []
            elements = {'name': 'Name', 'url': 'URL', 'userName': 'Login', 'password': 'Password'}
            for elem in tree.iter('Bean'):
                values = {}
                for e in elem:
                    if e.tag in elements:
                        values[elements[e.tag]] = e.text
                if values:
                    pwd_found.append(values)

            return pwd_found
