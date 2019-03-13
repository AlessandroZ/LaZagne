# -*- coding: utf-8 -*-

import os

try: 
    import _winreg as winreg
except ImportError:
    import winreg

import lazagne.config.winstructure as win
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import string_to_unicode


class Turba(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'turba', 'games', registry_used=True)

    def run(self):
        creds = []
        results = None

        # Find the location of steam - to make it easier we're going to use a try block
        # 'cos I'm lazy
        try:
            with win.OpenKey(win.HKEY_CURRENT_USER, 'Software\Valve\Steam') as key:
                results = winreg.QueryValueEx(key, 'SteamPath')
        except Exception:
            pass

        if results:
            steampath = string_to_unicode(results[0])
            steamapps = os.path.join(steampath, u'SteamApps\common')

            # Check that we have a SteamApps directory
            if not os.path.exists(steamapps):
                self.error(u'Steam doesn\'t have a SteamApps directory.')
                return

            filepath = os.path.join(steamapps, u'Turba\\Assets\\Settings.bin')

            if not os.path.exists(filepath):
                self.debug(u'Turba doesn\'t appear to be installed.')
                return

            # If we're here we should have a valid config file file
            with open(filepath, mode='rb') as filepath:
                # We've found a config file, now extract the creds
                data = filepath.read()
                chunk = data[0x1b:].split('\x0a')
                creds.append({
                    'Login': chunk[0],
                    'Password': chunk[1]
                })
            return creds
