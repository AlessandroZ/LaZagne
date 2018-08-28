# -*- coding: utf-8 -*- 
try: 
    import _winreg as winreg
except ImportError:
    import winreg

from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import *

# Password are stored in cleartext on old system (< 2008 R2 and < Win7)
# If enabled on recent system, the password should be visible on the lsa secrets dump (check lsa module output)


class Autologon(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'autologon', 'windows', registry_used=True, system_module=True)

    def run(self):
        pwd_found = []
        try:
            hkey = OpenKey(HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            if int(winreg.QueryValueEx(hkey, 'AutoAdminLogon')[0]) == 1:
                self.debug(u'Autologin enabled')

                keys = {
                    'DefaultDomainName': '',
                    'DefaultUserName': '',
                    'DefaultPassword': '',
                    'AltDefaultDomainName': '',
                    'AltDefaultUserName': '',
                    'AltDefaultPassword': '',
                }

                to_remove = []
                for k in keys:
                    try:
                        keys[k] = str(winreg.QueryValueEx(hkey, k)[0])
                    except Exception:
                        to_remove.append(k)

                for r in to_remove:
                    keys.pop(r)

                if keys:
                    pwd_found.append(keys)

        except Exception as e:
            self.debug(str(e))

        return pwd_found
