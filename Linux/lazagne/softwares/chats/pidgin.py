#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import os
import traceback

from lazagne.config.module_info import ModuleInfo
from xml.etree.cElementTree import ElementTree
from lazagne.config import homes


class Pidgin(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'pidgin', 'chats')

    # If pidgin is started, use the api to retrieve all passwords
    def get_password_from_dbus(self):

        try:
            import dbus
        except ImportError:
            self.debug('Dbus not installed: sudo apt-get install python-dbus')
            return []

        pwd_found = []
        for _, session in homes.sessions():
            try:
                bus = dbus.bus.BusConnection(session)
                purple = bus.get_object(
                    "im.pidgin.purple.PurpleService",
                    "/im/pidgin/purple/PurpleObject",
                    "im.pidgin.purple.PurpleInterface"
                )
                acc = purple.PurpleAccountsGetAllActive()

                for x in range(len(acc)):
                    _acc = purple.PurpleAccountsGetAllActive()[x]
                    pwd_found.append({
                        'Login': purple.PurpleAccountGetUsername(_acc),
                        'Password': purple.PurpleAccountGetPassword(_acc),
                        'Protocol': purple.PurpleAccountGetProtocolName(_acc),
                    })

                bus.flush()
                bus.close()

            except Exception as e:
                self.debug(e)

        return pwd_found

    def run(self):
        pwd_found = self.get_password_from_dbus()

        for path in homes.get(file=os.path.join('.purple', 'accounts.xml')):
            tree = ElementTree(file=path)
            root = tree.getroot()

            for account in root.findall('account'):
                if account.find('name') is not None:
                    name = account.find('name')
                    password = account.find('password')

                    if name is not None and password is not None:
                        pwd_found.append(
                            {
                                'Login': name.text,
                                'Password': password.text
                            }
                        )

        return pwd_found
