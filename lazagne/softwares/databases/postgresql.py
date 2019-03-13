# -*- coding: utf-8 -*-

import os

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo


class PostgreSQL(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, name='postgresql', category='databases')

    def run(self):
        path = os.path.join(constant.profile['APPDATA'], u'postgresql', u'pgpass.conf')
        if os.path.exists(path):
            with open(path) as f:
                pwd_found = []
                for line in f.readlines():
                    try:
                        items = line.strip().split(':')
                        pwd_found.append({
                            'Hostname': items[0],
                            'Port': items[1],
                            'DB': items[2],
                            'Username': items[3],
                            'Password': items[4]
                        })

                    except Exception:
                        pass

                return pwd_found
