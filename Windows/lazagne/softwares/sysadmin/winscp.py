# -*- coding: utf-8 -*- 
try: 
    import _winreg as winreg
except ImportError:
    import winreg

from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import OpenKey, HKEY_CURRENT_USER


class WinSCP(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'winscp', 'sysadmin', registry_used=True)
        self.hash = ''

    # ------------------------------ Getters and Setters ------------------------------
    def decrypt_char(self):
        hex_flag = 0xA3
        charset = '0123456789ABCDEF'

        if len(self.hash) > 0:
            unpack1 = charset.find(self.hash[0])
            unpack1 = unpack1 << 4

            unpack2 = charset.find(self.hash[1])
            result = ~((unpack1 + unpack2) ^ hex_flag) & 0xff

            # store the new hash
            self.hash = self.hash[2:]

            return result

    def check_winscp_installed(self):
        try:
            key = OpenKey(HKEY_CURRENT_USER, 'Software\\Martin Prikryl\\WinSCP 2\\Configuration\\Security')
            return key
        except Exception as e:
            self.debug(str(e))
            return False

    def check_masterPassword(self, key):
        is_master_pwd_used = winreg.QueryValueEx(key, 'UseMasterPassword')[0]
        winreg.CloseKey(key)
        if str(is_master_pwd_used) == '0':
            return False
        else:
            return True

    def get_credentials(self):
        try:
            key = OpenKey(HKEY_CURRENT_USER, 'Software\\Martin Prikryl\\WinSCP 2\\Sessions')
        except Exception as e:
            self.debug(str(e))
            return False

        pwd_found = []
        num_profiles = winreg.QueryInfoKey(key)[0]
        for n in range(num_profiles):
            name_skey = winreg.EnumKey(key, n)
            skey = OpenKey(key, name_skey)
            num = winreg.QueryInfoKey(skey)[1]

            values = {}
            elements = {'HostName': 'URL', 'UserName': 'Login', 'PortNumber': 'Port', 'Password': 'Password'}
            for nn in range(num):
                k = winreg.EnumValue(skey, nn)

                for e in elements:
                    if k[0] == e:
                        if e == 'Password':
                            try:
                                values['Password'] = self.decrypt_password(
                                    username=values.get('Login', ''),
                                    hostname=values.get('URL', ''),
                                    _hash=k[1]
                                )
                            except Exception as e:
                                self.debug(str(e))
                        else:
                            values[elements[k[0]]] = str(k[1])

            if num != 0:
                if 'Port' not in values:
                    values['Port'] = '22'

                pwd_found.append(values)

            winreg.CloseKey(skey)
        winreg.CloseKey(key)

        return pwd_found

    def decrypt_password(self, username, hostname, _hash):
        self.hash = _hash
        hex_flag = 0xFF

        flag = self.decrypt_char()
        if flag == hex_flag:
            self.decrypt_char()
            length = self.decrypt_char()
        else:
            length = flag

        ldel = (self.decrypt_char()) * 2
        self.hash = self.hash[ldel: len(self.hash)]

        result = ''
        for ss in range(length):

            try:
                result += chr(int(self.decrypt_char()))
            except Exception as e:
                self.debug(str(e))

        if flag == hex_flag:
            key = username + hostname
            result = result[len(key): len(result)]

        return result

    def run(self):
        winscp_key = self.check_winscp_installed()
        if winscp_key:
            if not self.check_masterPassword(winscp_key):
                results = self.get_credentials()
                if results:
                    return results
            else:
                self.warning(u'A master password is used. Passwords cannot been retrieved')
