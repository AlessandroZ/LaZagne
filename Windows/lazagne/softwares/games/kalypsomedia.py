# -*- coding: utf-8 -*- 
import base64
import os

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import char_to_int, chr_or_byte

try:
    from ConfigParser import ConfigParser  # Python 2.7
except ImportError:
    from configparser import ConfigParser  # Python 3


class KalypsoMedia(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'kalypsomedia', 'games')

    def xorstring(self, s, k):
        """
        xors the two strings
        """
        return b''.join(chr_or_byte(char_to_int(x) ^ char_to_int(y)) for x, y in zip(s, k))

    def run(self):
        creds = []
        key = b'lwSDFSG34WE8znDSmvtwGSDF438nvtzVnt4IUv89'
        inifile = os.path.join(constant.profile['APPDATA'], u'Kalypso Media\\Launcher\\launcher.ini')

        # The actual user details are stored in *.userdata files
        if os.path.exists(inifile):
            config = ConfigParser()
            config.read(inifile)

            # get the encoded password
            cookedpw = base64.b64decode(config.get('styx user', 'password'))

            creds.append({
                'Login': config.get('styx user', 'login'),
                'Password': self.xorstring(cookedpw, key)
            })
            return creds
