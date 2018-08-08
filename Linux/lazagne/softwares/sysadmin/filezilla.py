#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import base64

from xml.etree.cElementTree import ElementTree

from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes


class Filezilla(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'filezilla', 'sysadmin')

    def run(self):

        pwd_found = []
        for xml_file in homes.get(file=[
            os.path.join(d, f)
            for d in ('.filezilla', '.config/filezilla')
            for f in ('sitemanager.xml', 'recentservers.xml', 'filezilla.xml')
        ]):

            if os.path.exists(xml_file):
                tree = ElementTree(file=xml_file)
                servers = tree.findall('Servers/Server') if tree.findall('Servers/Server') else tree.findall(
                    'RecentServers/Server')

                for server in servers:
                    host = server.find('Host')
                    port = server.find('Port')
                    login = server.find('User')
                    password = server.find('Pass')

                    if host is not None and port is not None and login is not None:
                        values = {
                            'Host': host.text,
                            'Port': port.text,
                            'Login': login.text,
                        }

                    if password is not None:
                        if 'encoding' in password.attrib and password.attrib['encoding'] == 'base64':
                            values['Password'] = base64.b64decode(password.text)
                        else:
                            values['Password'] = password.text

                    pwd_found.append(values)

        return pwd_found
