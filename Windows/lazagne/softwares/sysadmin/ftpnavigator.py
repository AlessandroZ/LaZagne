# -*- coding: utf-8 -*- 
import struct

from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import constant

import os


class FtpNavigator(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'ftpnavigator', 'sysadmin', system_module=True)

    def decode(self, encode_password):
        password = ''
        for p in encode_password:
            password += chr(struct.unpack('B', p)[0] ^ 0x19)
        return password

    def run(self):
        path = os.path.join(constant.profile['HOMEDRIVE'], u'\\FTP Navigator', u'Ftplist.txt')
        elements = {'Name': 'Name', 'Server': 'Host', 'Port': 'Port', 'User': 'Login', 'Password': 'Password'}
        if os.path.exists(path):
            pwd_found = []
            with open(path, 'r') as f:
                for ff in f:
                    values = {}
                    info = ff.split(';')
                    for i in info:
                        i = i.split('=')
                        for e in elements:
                            if i[0] == e:
                                if i[0] == "Password" and i[1] != '1' and i[1] != '0':
                                    values['Password'] = self.decode(i[1])
                                else:
                                    values[elements[i[0]]] = i[1]

                    # used to save the password if it is an anonymous authentication
                    if values['Login'] == 'anonymous' and 'Password' not in values:
                        values['Password'] = 'anonymous'

                    pwd_found.append(values)

            return pwd_found
