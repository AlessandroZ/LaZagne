# Code based on vncpasswd.py by trinitronx
# https://github.com/trinitronx/vncpasswd.py
import binascii
import codecs
import traceback

try:
    import _winreg as winreg
except ImportError:
    import winreg

from . import d3des as d
from lazagne.config.winstructure import *
from lazagne.config.module_info import ModuleInfo


class Vnc(ModuleInfo):
    def __init__(self):
        self.vnckey = [23, 82, 107, 6, 35, 78, 88, 7]
        ModuleInfo.__init__(self, name='vnc', category='sysadmin')

    def split_len(self, seq, length):
        return [seq[i:i + length] for i in range(0, len(seq), length)]

    def do_crypt(self, password, decrypt):
        passpadd = (password + '\x00' * 8)[:8]
        strkey = ''.join([chr(x) for x in self.vnckey])
        key = d.deskey(strkey, decrypt)
        crypted = d.desfunc(passpadd, key)
        return crypted

    def unhex(self, s):
        try:
            s = codecs.decode(s, 'hex')
        except TypeError as e:
            if e.message == 'Odd-length string':
                self.debug('%s . Chopping last char off... "%s"' % (e.message, s[:-1]))
                s = codecs.decode(s[:-1], 'hex')
            else:
                return False
        return s

    def reverse_vncpassword(self, hash):
        encpasswd = self.unhex(hash)
        pwd = None
        if encpasswd:
            # If the hex encoded passwd length is longer than 16 hex chars and divisible
            # by 16, then we chop the passwd into blocks of 64 bits (16 hex chars)
            # (1 hex char = 4 binary bits = 1 nibble)
            hexpasswd = codecs.encode(encpasswd, 'hex')
            if len(hexpasswd) > 16 and (len(hexpasswd) % 16) == 0:
                splitstr = self.split_len(codecs.encode(hash, 'hex'), 16)
                cryptedblocks = []
                for sblock in splitstr:
                    cryptedblocks.append(self.do_crypt(codecs.decode(sblock, 'hex'), True))
                    pwd = ''.join(cryptedblocks)
            elif len(hexpasswd) <= 16:
                pwd = self.do_crypt(encpasswd, True)
            else:
                pwd = self.do_crypt(encpasswd, True)
        return pwd

    def vnc_from_registry(self):
        pfound = []
        vncs = (
            ('RealVNC 4.x', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\RealVNC\\WinVNC4', 'Password'),
            ('RealVNC 3.x', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\RealVNC\\vncserver', 'Password'),
            ('RealVNC 4.x', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\RealVNC\\WinVNC4', 'Password'),
            ('RealVNC 4.x', 'HKEY_CURRENT_USER\\SOFTWARE\\RealVNC\\WinVNC4', 'Password'),
            ('RealVNC 3.x', 'HKEY_CURRENT_USER\\Software\\ORL\\WinVNC3', 'Password'),
            ('TightVNC', 'HKEY_CURRENT_USER\\Software\\TightVNC\\Server', 'Password'),
            ('TightVNC', 'HKEY_CURRENT_USER\\Software\\TightVNC\\Server', 'PasswordViewOnly'),
            ('TightVNC', 'HKEY_LOCAL_MACHINE\\Software\\TightVNC\\Server', 'Password'),
            ('TightVNC ControlPassword', 'HKEY_LOCAL_MACHINE\\Software\\TightVNC\\Server', 'ControlPassword'),
            ('TightVNC', 'HKEY_LOCAL_MACHINE\\Software\\TightVNC\\Server', 'PasswordViewOnly'),
            ('TigerVNC', 'HKEY_LOCAL_MACHINE\\Software\\TigerVNC\\Server', 'Password'),
            ('TigerVNC', 'HKEY_CURRENT_USER\\Software\\TigerVNC\\Server', 'Password'),
        )

        for vnc in vncs:
            try:
                if vnc[1].startswith('HKEY_LOCAL_MACHINE'):
                    hkey = OpenKey(HKEY_LOCAL_MACHINE, vnc[1].replace('HKEY_LOCAL_MACHINE\\', ''))

                elif vnc[1].startswith('HKEY_CURRENT_USER'):
                    hkey = OpenKey(HKEY_CURRENT_USER, vnc[1].replace('HKEY_CURRENT_USER\\', ''))

                reg_key = winreg.QueryValueEx(hkey, vnc[2])[0]
            except Exception:
                self.debug(u'Problems with key:: {reg_key}'.format(reg_key=vnc[1]))
                continue

            try:
                enc_pwd = binascii.hexlify(reg_key).decode()
            except Exception:
                self.debug(u'Problems with decoding: {reg_key}'.format(reg_key=reg_key))
                continue

            values = {}
            try:
                password = self.reverse_vncpassword(enc_pwd)
                if password:
                    values['Password'] = password
            except Exception:
                self.info(u'Problems with reverse_vncpassword: {reg_key}'.format(reg_key=reg_key))
                self.debug()
                continue

            values['Server'] = vnc[0]
            # values['Hash'] = enc_pwd
            pfound.append(values)

        return pfound

    def vnc_from_filesystem(self):
        # os.environ could be used here because paths are identical between users
        pfound = []
        vncs = (
            ('UltraVNC', os.environ['ProgramFiles(x86)'] + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', 'passwd'),
            ('UltraVNC', os.environ['ProgramFiles(x86)'] + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', 'passwd2'),
            ('UltraVNC', os.environ['PROGRAMFILES'] + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', 'passwd'),
            ('UltraVNC', os.environ['PROGRAMFILES'] + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', 'passwd2'),
            ('UltraVNC', os.environ['PROGRAMFILES'] + '\\UltraVNC\\ultravnc.ini', 'passwd'),
            ('UltraVNC', os.environ['PROGRAMFILES'] + '\\UltraVNC\\ultravnc.ini', 'passwd2'),
            ('UltraVNC', os.environ['ProgramFiles(x86)'] + '\\UltraVNC\\ultravnc.ini', 'passwd'),
            ('UltraVNC', os.environ['ProgramFiles(x86)'] + '\\UltraVNC\\ultravnc.ini', 'passwd2'),
        )

        for vnc in vncs:
            string_to_match = vnc[2] + '='
            enc_pwd = ''
            try:
                with open(vnc[1], 'r') as file:
                    for line in file:
                        if string_to_match in line:
                            enc_pwd = line.replace(string_to_match, '').replace('\n', '')
            except Exception:
                self.debug('Problems with file: {file}'.format(file=vnc[1]))
                continue

            values = {}
            try:
                password = self.reverse_vncpassword(enc_pwd)
                if password:
                    values['Password'] = password
            except Exception:
                self.debug(u'Problems with reverse_vncpassword: {enc_pwd}'.format(enc_pwd=enc_pwd))
                self.debug(traceback.format_exc())
                continue

            values['Server'] = vnc[0]
            # values['Hash'] = enc_pwd
            pfound.append(values)

        return pfound

    def vnc_from_process(self):
        # Not yet implemented
        return []

    def run(self):
        return self.vnc_from_filesystem() + self.vnc_from_registry() + self.vnc_from_process()
