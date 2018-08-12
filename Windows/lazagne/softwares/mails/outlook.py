# -*- coding: utf-8 -*- 
import _winreg

import lazagne.config.winstructure as win
from lazagne.config.module_info import ModuleInfo


class Outlook(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'outlook', 'mails', registry_used=True, dpapi_used=True)

    def run(self):
        key_path = 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook'
        try:
            hkey = win.OpenKey(win.HKEY_CURRENT_USER, key_path)
        except Exception as e:
            self.debug(e)
            return

        num = _winreg.QueryInfoKey(hkey)[0]
        pwd_found = []
        for x in range(0, num):
            name = _winreg.EnumKey(hkey, x)
            skey = win.OpenKey(hkey, name, 0, win.ACCESS_READ)

            num_skey = _winreg.QueryInfoKey(skey)[0]
            if num_skey != 0:
                for y in range(0, num_skey):
                    name_skey = _winreg.EnumKey(skey, y)
                    sskey = win.OpenKey(skey, name_skey)
                    num_sskey = _winreg.QueryInfoKey(sskey)[1]

                    for z in range(0, num_sskey):
                        k = _winreg.EnumValue(sskey, z)
                        if 'password' in k[0].lower():
                            values = self.retrieve_info(sskey, name_skey)

                            if values:
                                pwd_found.append(values)

            _winreg.CloseKey(skey)
        _winreg.CloseKey(hkey)
        return pwd_found

    def retrieve_info(self, hkey, name_key):
        values = {}
        num = _winreg.QueryInfoKey(hkey)[1]
        for x in range(0, num):
            k = _winreg.EnumValue(hkey, x)
            if 'password' in k[0].lower():
                try:
                    password = win.Win32CryptUnprotectData(k[1][1:])
                    values[k[0]] = password.decode('utf16')
                except Exception as e:
                    self.debug(str(e))
                    values[k[0]] = 'N/A'
            else:
                try:
                    values[k[0]] = str(k[1]).decode('utf16')
                except Exception:
                    values[k[0]] = str(k[1])
        return values
