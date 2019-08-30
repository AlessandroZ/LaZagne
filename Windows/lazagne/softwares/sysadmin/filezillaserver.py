# -*- coding: utf-8 -*-
from xml.etree.cElementTree import ElementTree

from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import constant

import os


class FilezillaServer(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'filezillaserver', 'sysadmin')

    def run(self):
        path = os.path.join(constant.profile['APPDATA'], u'FileZilla Server')
        if os.path.exists(path):
            pwd_found = []
            file = u'FileZilla Server Interface.xml'

            xml_file = os.path.join(path, file)

            if os.path.exists(xml_file):
                tree = ElementTree(file=xml_file)
                root = tree.getroot()
                host = port = password = None

                for item in root.iter("Item"):
                    if item.attrib['name'] == 'Last Server Address':
                        host = item.text
                    elif item.attrib['name'] == 'Last Server Port':
                        port = item.text
                    elif item.attrib['name'] == 'Last Server Password':
                        password = item.text
                # if all((host, port, login)) does not work
                if host is not None and port is not None and password is not None:
                    pwd_found = [{
                        'Host': host,
                        'Port': port,
                        'Password': password,
                    }]

            return pwd_found
