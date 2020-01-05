# -*- coding: utf-8 -*- 
import base64

from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import Win32CryptUnprotectData
from lazagne.config.constant import constant

import os


class Tortoise(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'tortoise', 'svn', winapi_used=True)

    def run(self):
        pwd_found = []
        path = os.path.join(constant.profile["APPDATA"], u'Subversion\\auth\\svn.simple')
        if os.path.exists(path):
            for root, dirs, files in os.walk(path + os.sep):
                for filename in files:
                    f = open(os.path.join(path, filename), 'r')
                    url = ''
                    username = ''
                    result = ''

                    i = 0
                    # password
                    for line in f:
                        if i == -1:
                            result = line.replace('\n', '')
                            break
                        if line.startswith('password'):
                            i = -3
                        i += 1

                    i = 0
                    # url
                    for line in f:
                        if i == -1:
                            url = line.replace('\n', '')
                            break
                        if line.startswith('svn:realmstring'):
                            i = -3
                        i += 1

                    i = 0

                    # username
                    for line in f:
                        if i == -1:
                            username = line.replace('\n', '')
                            break
                        if line.startswith('username'):
                            i = -3
                        i += 1

                    # encrypted the password
                    if result:
                        try:
                            password_bytes = Win32CryptUnprotectData(base64.b64decode(result), is_current_user=constant.is_current_user, user_dpapi=constant.user_dpapi)
                            pwd_found.append({
                                'URL': url,
                                'Login': username,
                                'Password': password_bytes.decode("utf-8")
                            })
                        except Exception:
                            pass
            return pwd_found
