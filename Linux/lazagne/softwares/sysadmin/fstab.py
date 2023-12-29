#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import os

from lazagne.config.module_info import ModuleInfo


class Fstab(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'fstab', 'sysadmin')

    def run(self):
        pwd_found = []
        path = '/etc/fstab'
        if os.path.exists(path):
            try:
                with open(path) as fstab:
                    for line in fstab:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue

                        filesystem, mount_point, _type, options, dump, _pass = line.split()
                        if 'pass' in options or 'cred' in options:
                            pwd_found.append({
                                'Filesystem': filesystem,
                                'Mount Point': mount_point,
                                'Type': _type,
                                'Password': options
                             })

            except IOError as e:
                self.debug(e.strerror)

        return pwd_found
