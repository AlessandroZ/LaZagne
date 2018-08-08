#!/usr/bin/env python
# -*- coding: utf-8 -*- 

#######################
#
# By Quentin HARDY
#
#######################

from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes


class Kde(ModuleInfo):
    def __init__(self):
        self.appid = 'Get KDE keyring'
        self.bus_info = [
            ('org.kde.kwalletd', '/modules/kwalletd'),
            ('org.kde.kwalletd5', '/modules/kwalletd5')
        ]
        ModuleInfo.__init__(self, 'kwallet', 'wallet')

    def run(self):

        try:
            import dbus
        except Exception as e:
            self.error('kwallet: {error}'.format(error=e))
            return []

        pwd_found = []
        for _, session in homes.sessions():
            try:
                bus = dbus.bus.BusConnection(session)

                if 'org.kde.kwalletd' not in [str(x) for x in bus.list_names()]:
                    continue

                for info in self.bus_info:
                    kwallet_object = bus.get_object(info[0], info[1])

                    wallet = dbus.Interface(kwallet_object, 'org.kde.KWallet')
                    handle = wallet.open(wallet.networkWallet(), 0, self.appid)

                    if handle:
                        for folder in wallet.folderList(handle, self.appid):
                            for entry in wallet.entryList(handle, folder, self.appid):
                                password_list = wallet.readPasswordList(handle, folder, entry, self.appid)
                                for plist in password_list.items():
                                    pwd_found.append({
                                        'Folder': str(folder),
                                        'Login': str(plist[0]),
                                        'Password': str(plist[1]),
                                    })

            except Exception as e:
                self.error(e)
                continue

            bus.flush()
            bus.close()

        return pwd_found
