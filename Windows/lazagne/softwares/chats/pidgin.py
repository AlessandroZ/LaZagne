# -*- coding: utf-8 -*- 
import os
from xml.etree.cElementTree import ElementTree

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo


class Pidgin(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'pidgin', 'chats')

    def run(self):
        path = os.path.join(constant.profile['APPDATA'], u'.purple', u'accounts.xml')
        if os.path.exists(path):
            tree = ElementTree(file=path)
            root = tree.getroot()
            pwd_found = []

            for account in root.findall('account'):
                name = account.find('name')
                password = account.find('password')
                if all((name, password)):
                    pwd_found.append({
                        'Login': name.text,
                        'Password': password.text
                    })
            return pwd_found
