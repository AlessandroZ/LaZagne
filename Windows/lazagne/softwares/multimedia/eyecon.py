# -*- coding: utf-8 -*-
import codecs

try:
    import _winreg as winreg
except ImportError:
    import winreg

from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import *


class EyeCON(ModuleInfo):
    """
    eyeCON software WAll management software
    infos at http://www.eyevis.de/en/products/wall-management-software.html
    """
    def __init__(self):
        self.hex_key = [ 35, 231, 64, 111, 100, 72, 95, 65, 68, 51, 52, 70, 67, 51, 65, 95, 54, 55, 50, 48, 95, 49, 49,
             68, 54, 95, 65, 48, 53, 50, 95, 48, 48, 48, 52, 55, 54, 65, 48, 70, 66, 53, 66, 65, 70, 88, 95, 76, 79, 71,
             73, 49, 76, 115, 107, 100, 85, 108, 107, 106, 102, 100, 109, 32, 50, 102, 115, 100, 102, 102, 32, 102, 119,
             115, 38, 78, 68, 76, 76, 95, 72, 95, 95, 0 ]
        ModuleInfo.__init__(self, name='EyeCon', category='multimedia')

    def deobfuscate(self, ciphered_str):
        return b''.join([chr_or_byte(char_to_int(c) ^ k) for c, k in zip(codecs.decode(ciphered_str, 'hex'), self.hex_key)])

    def get_db_hosts(self):
        hosts = []
        paths = (
            ('EyeCON DB Host', HKEY_LOCAL_MACHINE, 'SOFTWARE\\WOW6432Node\\eyevis\\eyeDB', 'DB1'),
            ('EyeCON DB Host', HKEY_LOCAL_MACHINE, 'SOFTWARE\\WOW6432Node\\eyevis\\eyeDB', 'DB2'),
            ('EyeCON DB Host', HKEY_LOCAL_MACHINE, 'SOFTWARE\\WOW6432Node\\eyevis\\eyeDB', 'DB3'),
            ('EyeCON DB Host', HKEY_LOCAL_MACHINE, 'SOFTWARE\\eyevis\\eyeDB', 'DB1'),
            ('EyeCON DB Host', HKEY_LOCAL_MACHINE, 'SOFTWARE\\eyevis\\eyeDB', 'DB2'),
            ('EyeCON DB Host', HKEY_LOCAL_MACHINE, 'SOFTWARE\\eyevis\\eyeDB', 'DB3'),
        )
        for path in paths:
            try:
                hkey = OpenKey(path[1], path[2])
                reg_key = winreg.QueryValueEx(hkey, path[3])[0]
                if reg_key:
                    hosts += [reg_key]
            except Exception:
                # skipping if value doesn't exist
                # self.debug(u'Problems with key:: {reg_key}'.format(reg_key=path[1]+path[2]))
                pass
        return hosts

    def credentials_from_registry(self):
        found_passwords = []
        password_path = (
            {
                'app': 'EyeCON', 'reg_root': HKEY_LOCAL_MACHINE,
                'reg_path': 'SOFTWARE\\WOW6432Node\\eyevis\\eyetool\\Default',
                'user_key': 'registered', 'password_key': 'connection'
            },
            {
                'app': 'EyeCON', 'reg_root': HKEY_LOCAL_MACHINE,
                'reg_path': 'SOFTWARE\\eyevis\\eyetool\\Default',
                'user_key': 'registered', 'password_key': 'connection'
            },
        )

        for path in password_path:
            values = {}
            try:
                try:
                    hkey = OpenKey(path['reg_root'], path['reg_path'])
                    reg_user_key = winreg.QueryValueEx(hkey, path['user_key'])[0]
                    reg_password_key = winreg.QueryValueEx(hkey, path['password_key'])[0]
                except Exception:
                    self.debug(u'Problems with key:: {reg_key}'.format(reg_key=path['reg_root'] + path['reg_path']))
                    continue

                try:
                    user = self.deobfuscate(reg_user_key)
                except Exception:
                    self.info(u'Problems with deobfuscate user : {reg_key}'.format(reg_key=path['reg_path']))
                    continue

                try:
                    password = self.deobfuscate(reg_password_key)
                except Exception:
                    self.info(u'Problems with deobfuscate password : {reg_key}'.format(reg_key=path['reg_path']))
                    continue

                found_passwords.append({'username': user, 'password': password})
            except Exception:
                pass
        return found_passwords

    def run(self):
        hosts = self.get_db_hosts()
        credentials = self.credentials_from_registry()
        for cred in credentials:
            cred['host(s)'] = b', '.join(hosts)
        return credentials
