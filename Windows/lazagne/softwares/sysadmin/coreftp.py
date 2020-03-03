# -*- coding: utf-8 -*- 
import binascii
try: 
    import _winreg as winreg
except ImportError:
    import winreg

from lazagne.config.crypto.pyaes.aes import AESModeOfOperationECB
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import OpenKey, HKEY_CURRENT_USER


class CoreFTP(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'coreftp', 'sysadmin')

        self._secret = b"hdfzpysvpzimorhk"

    def decrypt(self, hex):
        encoded = binascii.unhexlify(hex)
        aes = AESModeOfOperationECB(self._secret)
        decrypted = aes.decrypt(encoded)
        return decrypted.split(b'\x00')[0]

    def run(self):
        key = None
        pwd_found = []
        try:
            key = OpenKey(HKEY_CURRENT_USER, 'Software\\FTPware\\CoreFTP\\Sites')
        except Exception as e:
            self.debug(str(e))

        if key:
            num_profiles = winreg.QueryInfoKey(key)[0]
            elements = ['Host', 'Port', 'User', 'PW']
            for n in range(num_profiles):
                name_skey = winreg.EnumKey(key, n)
                skey = OpenKey(key, name_skey)
                num = winreg.QueryInfoKey(skey)[1]
                values = {}
                for nn in range(num):
                    k = winreg.EnumValue(skey, nn)
                    if k[0] in elements:
                        if k[0] == 'User':
                            values['Login'] = k[1]
                            pwd_found.append(values)
                        if k[0] == 'PW':
                            try:
                                values['Password'] = self.decrypt(k[1])
                            except Exception as e:
                                self.debug(str(e))
                        else:
                            values[k[0]] = k[1]

                winreg.CloseKey(skey)
            winreg.CloseKey(key)

            return pwd_found
