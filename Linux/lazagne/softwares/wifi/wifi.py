#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import os

from lazagne.config.module_info import ModuleInfo


try:
    from ConfigParser import RawConfigParser  # Python 2.7
except ImportError:
    from configparser import RawConfigParser  # Python 3

from collections import OrderedDict


class Wifi(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'wifi', 'wifi')

    def run(self):
        pwd_found = []
        directory = u'/etc/NetworkManager/system-connections'

        if os.path.exists(directory):
            if os.getuid() == 0:
                wireless_ssid = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]

                for w in wireless_ssid:
                    cp = RawConfigParser()
                    cp.read(os.path.join(directory, w))
                    values = OrderedDict()
                    try:
                        values['SSID'] = cp.get('wifi', 'ssid')
                        values['Password'] = cp.get('wifi-security', 'psk')
                        pwd_found.append(values)
                    except Exception:
                        pass

            else:
                self.info('You need sudo privileges')

            return pwd_found
