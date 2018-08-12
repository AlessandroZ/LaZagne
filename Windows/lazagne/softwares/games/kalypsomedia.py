# -*- coding: utf-8 -*- 
import ConfigParser
import base64
import os

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo


class KalypsoMedia(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'kalypsomedia', 'games')

    def xorstring(self, s, k):
        """
        xors the two strings
        """
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(s, k))

    def run(self):
        creds = []
        key = 'lwSDFSG34WE8znDSmvtwGSDF438nvtzVnt4IUv89'
        inifile = os.path.join(constant.profile['APPDATA'], u'Kalypso Media\\Launcher\\launcher.ini')

        # The actual user details are stored in *.userdata files
        if os.path.exists(inifile):
            config = ConfigParser.ConfigParser()
            config.read(inifile)

            # get the encoded password
            cookedpw = base64.b64decode(config.get('styx user', 'password'))

            creds.append({
                'Login': config.get('styx user', 'login'),
                'Password': self.xorstring(cookedpw, key)
            })
            return creds
