#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Thanks to https://github.com/b4n/clawsmail-password-decrypter
from Crypto.Cipher import DES
from base64 import standard_b64decode as b64decode
from ConfigParser import ConfigParser
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.write_output import print_debug
import platform, os

class ClawsMail(ModuleInfo):
    def __init__(self):
        options = {'command': '-c', 'action': 'store_true', 'dest': 'clawsmail', 'help': 'clawsmail'}
        ModuleInfo.__init__(self, 'clawsmail', 'mails', options)    

    def run(self, software_name = None):
        path = self.get_path()
        if not path:
            print_debug('INFO', 'ClawsMail not installed.')
            return

        mode = DES.MODE_CFB
        if 'FreeBSD' in platform.system():
            mode = DES.MODE_ECB
                
        pwdFound = self.accountrc_decrypt(path, self.get_passcrypt_key(), mode)
        return pwdFound

    def get_path(self):
        file = '~/.claws-mail/accountrc'
        file = os.path.expanduser(file)
        if os.path.exists(file):
            return file
        else:
            return None

    def get_passcrypt_key(self):
        PASSCRYPT_KEY = b'passkey0'
        return PASSCRYPT_KEY

    def pass_decrypt(self, p, key, mode=DES.MODE_CFB):
        """ Decrypts a password from ClawsMail. """
        if p[0] == '!':  # encrypted password
            buf = b64decode(p[1:])

            """
            If mode is ECB or CBC and the length of the data is wrong, do nothing
            as would the libc algorithms (as they fail early).  Yes, this means the
            password wasn't actually encrypted but only base64-ed.
            """
            if (mode in (DES.MODE_ECB, DES.MODE_CBC)) and ((len(buf) % 8) != 0 or
                                                           len(buf) > 8192):
                return buf

            c = DES.new(key, mode=mode, IV=b'\0'*8)
            return c.decrypt(buf)
        else:  # raw password
            return p


    def accountrc_decrypt(self, filename, key, mode=DES.MODE_CFB):
        """ Reads passwords from ClawsMail's accountrc file """
        p = ConfigParser()
        p.read(filename)

        pwdFound = []
        for s in p.sections():
            values = {}
            try:
                try:
                    address = p.get(s, 'address')
                    account = p.get(s, 'account_name')
                except:
                    address = '<unknown>'
                    account = '<unknown>'

                password = self.pass_decrypt(p.get(s, 'password'), key, mode=mode)
                # print('password for %s, %s is "%s"' % (account, address, password))
                values = {'Login' : account, 'URL': address, 'Password': password}
            except Exception as e:
                print_debug('ERROR', 'Error resolving password for account "%s": %s' % (s, e))

             # write credentials into a text file
            if len(values) != 0:
                pwdFound.append(values)

        return pwdFound
