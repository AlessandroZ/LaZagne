#!/usr/bin/env python
# -*- coding: utf-8 -*-
# portable decryption functions and BSD DB parsing by Laurent Clevy (@lorenzo2472)
# from https://github.com/lclevy/firepwd/blob/master/firepwd.py

import hmac
import json
import sqlite3
import struct
import traceback
from base64 import b64decode
from binascii import unhexlify
from hashlib import sha1

from pyasn1.codec.der import decoder

from lazagne.config.constant import constant
from lazagne.config.crypto.pyDes import triple_des, CBC
from lazagne.config.dico import get_dic
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import char_to_int, convert_to_byte

try:
    from ConfigParser import RawConfigParser  # Python 2.7
except ImportError:
    from configparser import RawConfigParser  # Python 3
import os


def l(n):
    try:
        return long(n)
    except NameError:
        return int(n)


def long_to_bytes(n, blocksize=0):
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.
    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = convert_to_byte('')
    n = l(n)
    while n > 0:
        s = struct.pack('>I', n & 0xffffffff) + s
        n = n >> 32

    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != convert_to_byte('\000')[0]:
            break
    else:
        # only happens when n == 0
        s = convert_to_byte('\000')
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * convert_to_byte('\000') + s

    return s


class Mozilla(ModuleInfo):

    def __init__(self, browser_name, path):
        self.path = path
        ModuleInfo.__init__(self, browser_name, 'browsers')

    def get_firefox_profiles(self, directory):
        """
        List all profiles
        """
        cp = RawConfigParser()
        profile_list = []
        try:
            cp.read(os.path.join(directory, 'profiles.ini'))
            for section in cp.sections():
                if section.startswith('Profile') and cp.has_option(section, 'Path'):
                    profile_path = None

                    if cp.has_option(section, 'IsRelative'):
                        if cp.get(section, 'IsRelative') == '1':
                            profile_path = os.path.join(directory, cp.get(section, 'Path').strip())
                        elif cp.get(section, 'IsRelative') == '0':
                            profile_path = cp.get(section, 'Path').strip()

                    else: # No "IsRelative" in profiles.ini
                        profile_path = os.path.join(directory, cp.get(section, 'Path').strip())

                    if profile_path:
                        profile_list.append(profile_path)

        except Exception as e:
            self.error(u'An error occurred while reading profiles.ini: {}'.format(e))
        return profile_list

    def get_key(self, profile):
        """
        Get main key used to encrypt all data (user / password).
        Depending on the Firefox version, could be stored in key3.db or key4.db file.
        """
        try:
            row = None
            # Remove error when file is empty
            with open(os.path.join(profile, 'key4.db'), 'rb') as f:
                content = f.read()

            if content:
                conn = sqlite3.connect(os.path.join(profile, 'key4.db'))  # Firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
                c = conn.cursor()
                # First check password
                c.execute("SELECT item1,item2 FROM metadata WHERE id = 'password';")
                try:
                    row = c.next()  # Python 2
                except Exception:
                    row = next(c)  # Python 3

        except Exception:
            self.debug(traceback.format_exc())
        else:
            if row:
                (global_salt, master_password, entry_salt) = self.manage_masterpassword(master_password='', key_data=row)

                if global_salt:
                    # Decrypt 3DES key to decrypt "logins.json" content
                    c.execute("SELECT a11,a102 FROM nssPrivate;")
                    for row in c:
                        if row[0]:
                            break
                    a11 = row[0]  # CKA_VALUE
                    a102 = row[1]  # f8000000000000000000000000000001, CKA_ID
                    # self.print_asn1(a11, len(a11), 0)
                    # SEQUENCE {
                    #     SEQUENCE {
                    #         OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
                    #         SEQUENCE {
                    #             OCTETSTRING entry_salt_for_3des_key
                    #             INTEGER 01
                    #         }
                    #     }
                    #     OCTETSTRING encrypted_3des_key (with 8 bytes of PKCS#7 padding)
                    # }
                    decoded_a11 = decoder.decode(a11)
                    entry_salt = decoded_a11[0][0][1][0].asOctets()
                    cipher_t = decoded_a11[0][1].asOctets()
                    key = self.decrypt_3des(global_salt, master_password, entry_salt, cipher_t)
                    if key:
                        self.debug(u'key: {key}'.format(key=repr(key)))
                        yield key[:24]

        try:
            key_data = self.read_bsddb(os.path.join(profile, 'key3.db'))
            # Check masterpassword
            (global_salt, master_password, entry_salt) = self.manage_masterpassword(master_password='',
                                                                                    key_data=key_data,
                                                                                    new_version=False)
            if global_salt:
                key = self.extract_secret_key(key_data=key_data,
                                              global_salt=global_salt,
                                              master_password=master_password,
                                              entry_salt=entry_salt)
                if key:
                    self.debug(u'key: {key}'.format(key=repr(key)))
                    yield key[:24]
        except Exception:
            self.debug(traceback.format_exc())

    @staticmethod
    def get_short_le(d, a):
        return struct.unpack('<H', d[a:a + 2])[0]

    @staticmethod
    def get_long_be(d, a):
        return struct.unpack('>L', d[a:a + 4])[0]

    def print_asn1(self, d, l, rl):
        """
        Used for debug
        """
        type_ = char_to_int(d[0])
        length = char_to_int(d[1])
        if length & 0x80 > 0:  # http://luca.ntop.org/Teaching/Appunti/asn1.html,
            # nByteLength = length & 0x7f
            length = char_to_int(d[2])
            # Long form. Two to 127 octets. Bit 8 of first octet has value "1" and
            # bits 7-1 give the number of additional length octets.
            skip = 1
        else:
            skip = 0

        if type_ == 0x30:
            seq_len = length
            read_len = 0
            while seq_len > 0:
                len2 = self.print_asn1(d[2 + skip + read_len:], seq_len, rl + 1)
                seq_len = seq_len - len2
                read_len = read_len + len2
            return length + 2
        elif type_ in (0x6, 0x5, 0x4, 0x2):  # OID, OCTETSTRING, NULL, INTEGER
            return length + 2
        elif length == l - 2:
            self.print_asn1(d[2:], length, rl + 1)
            return length

    def read_bsddb(self, name):
        """
        Extract records from a BSD DB 1.85, hash mode
        Obsolete with Firefox 58.0.2 and NSS 3.35, as key4.db (SQLite) is used
        """
        with open(name, 'rb') as f:
            # http://download.oracle.com/berkeley-db/db.1.85.tar.gz
            header = f.read(4 * 15)
            magic = self.get_long_be(header, 0)
            if magic != 0x61561:
                self.error(u'Bad magic number')
                return False

            version = self.get_long_be(header, 4)
            if version != 2:
                self.error(u'Bad version !=2 (1.85)')
                return False

            pagesize = self.get_long_be(header, 12)
            nkeys = self.get_long_be(header, 0x38)
            readkeys = 0
            page = 1
            db1 = []

            while readkeys < nkeys:
                f.seek(pagesize * page)
                offsets = f.read((nkeys + 1) * 4 + 2)
                offset_vals = []
                i = 0
                nval = 0
                val = 1
                keys = 0

                while nval != val:
                    keys += 1
                    key = self.get_short_le(offsets, 2 + i)
                    val = self.get_short_le(offsets, 4 + i)
                    nval = self.get_short_le(offsets, 8 + i)
                    offset_vals.append(key + pagesize * page)
                    offset_vals.append(val + pagesize * page)
                    readkeys += 1
                    i += 4

                offset_vals.append(pagesize * (page + 1))
                val_key = sorted(offset_vals)
                for i in range(keys * 2):
                    f.seek(val_key[i])
                    data = f.read(val_key[i + 1] - val_key[i])
                    db1.append(data)
                page += 1

        db = {}
        for i in range(0, len(db1), 2):
            db[db1[i + 1]] = db1[i]

        return db

    @staticmethod
    def decrypt_3des(global_salt, master_password, entry_salt, encrypted_data):
        """
        User master key is also encrypted (if provided, the master_password could be used to encrypt it)
        """
        # See http://www.drh-consultancy.demon.co.uk/key3.html
        hp = sha1(global_salt + master_password.encode()).digest()
        pes = entry_salt + convert_to_byte('\x00') * (20 - len(entry_salt))
        chp = sha1(hp + entry_salt).digest()
        k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
        tk = hmac.new(chp, pes, sha1).digest()
        k2 = hmac.new(chp, tk + entry_salt, sha1).digest()
        k = k1 + k2
        iv = k[-8:]
        key = k[:24]
        return triple_des(key, CBC, iv).decrypt(encrypted_data)

    def extract_secret_key(self, key_data, global_salt, master_password, entry_salt):

        if unhexlify('f8000000000000000000000000000001') not in key_data:
            return None

        priv_key_entry = key_data[unhexlify('f8000000000000000000000000000001')]
        salt_len = char_to_int(priv_key_entry[1])
        name_len = char_to_int(priv_key_entry[2])
        priv_key_entry_asn1 = decoder.decode(priv_key_entry[3 + salt_len + name_len:])
        data = priv_key_entry[3 + salt_len + name_len:]
        # self.print_asn1(data, len(data), 0)

        # See https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
        entry_salt = priv_key_entry_asn1[0][0][1][0].asOctets()
        priv_key_data = priv_key_entry_asn1[0][1].asOctets()
        priv_key = self.decrypt_3des(global_salt, master_password, entry_salt, priv_key_data)
        # self.print_asn1(priv_key, len(priv_key), 0)
        priv_key_asn1 = decoder.decode(priv_key)
        pr_key = priv_key_asn1[0][2].asOctets()
        # self.print_asn1(pr_key, len(pr_key), 0)
        pr_key_asn1 = decoder.decode(pr_key)
        # id = pr_key_asn1[0][1]
        key = long_to_bytes(pr_key_asn1[0][3])
        return key

    @staticmethod
    def decode_login_data(data):
        asn1data = decoder.decode(b64decode(data))  # First base64 decoding, then ASN1DERdecode
        # For login and password, keep :(key_id, iv, ciphertext)
        return asn1data[0][0].asOctets(), asn1data[0][1][1].asOctets(), asn1data[0][2].asOctets()

    def get_login_data(self, profile):
        """
        Get encrypted data (user / password) and host from the json or sqlite files
        """
        conn = sqlite3.connect(os.path.join(profile, 'signons.sqlite'))
        logins = []
        c = conn.cursor()
        try:
            c.execute('SELECT * FROM moz_logins;')
        except sqlite3.OperationalError:  # Since Firefox 32, json is used instead of sqlite3
            try:
                logins_json = os.path.join(profile, 'logins.json')
                if os.path.isfile(logins_json):
                    with open(logins_json) as f:
                        loginf = f.read()
                        if loginf:
                            json_logins = json.loads(loginf)
                            if 'logins' not in json_logins:
                                self.debug('No logins key in logins.json')
                                return logins
                            for row in json_logins['logins']:
                                enc_username = row['encryptedUsername']
                                enc_password = row['encryptedPassword']
                                logins.append((self.decode_login_data(enc_username),
                                               self.decode_login_data(enc_password), row['hostname']))
                            return logins
            except Exception:
                self.debug(traceback.format_exc())
                return []

        # Using sqlite3 database
        for row in c:
            enc_username = row[6]
            enc_password = row[7]
            logins.append((self.decode_login_data(enc_username), self.decode_login_data(enc_password), row[1]))
        return logins

    def manage_masterpassword(self, master_password='', key_data=None, new_version=True):
        """
        Check if a master password is set.
        If so, try to find it using a dictionary attack
        """
        (global_salt, master_password, entry_salt) = self.is_master_password_correct(master_password=master_password,
                                                                                     key_data=key_data,
                                                                                     new_version=new_version)

        if not global_salt:
            self.info(u'Master Password is used !')
            (global_salt, master_password, entry_salt) = self.brute_master_password(key_data=key_data,
                                                                                    new_version=new_version)
            if not master_password:
                return '', '', ''

        return global_salt, master_password, entry_salt

    def is_master_password_correct(self, key_data, master_password='', new_version=True):
        try:
            if not new_version:
                # See http://www.drh-consultancy.demon.co.uk/key3.html
                pwd_check = key_data.get(b'password-check')
                if not pwd_check:
                    return '', '', ''
                entry_salt_len = char_to_int(pwd_check[1])
                entry_salt = pwd_check[3: 3 + entry_salt_len]
                encrypted_passwd = pwd_check[-16:]
                global_salt = key_data[b'global-salt']

            else:
                global_salt = key_data[0]  # Item1
                item2 = key_data[1]
                # self.print_asn1(item2, len(item2), 0)
                # SEQUENCE {
                # 	SEQUENCE {
                # 		OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
                # 		SEQUENCE {
                # 			OCTETSTRING entry_salt_for_passwd_check
                # 			INTEGER 01
                # 		}
                # 	}
                # 	OCTETSTRING encrypted_password_check
                # }
                decoded_item2 = decoder.decode(item2)
                entry_salt = decoded_item2[0][0][1][0].asOctets()
                encrypted_passwd = decoded_item2[0][1].asOctets()

            cleartext_data = self.decrypt_3des(global_salt, master_password, entry_salt, encrypted_passwd)
            if cleartext_data != convert_to_byte('password-check\x02\x02'):
                return '', '', ''

            return global_salt, master_password, entry_salt
        except Exception:
            self.debug(traceback.format_exc())
            return '', '', ''

    def brute_master_password(self, key_data, new_version=True):
        """
        Try to find master_password doing a dictionary attack using the 500 most used passwords
        """
        wordlist = constant.password_found + get_dic()
        num_lines = (len(wordlist) - 1)
        self.info(u'%d most used passwords !!! ' % num_lines)

        for word in wordlist:
            global_salt, master_password, entry_salt = self.is_master_password_correct(key_data=key_data,
                                                                                       master_password=word.strip(),
                                                                                       new_version=new_version)
            if master_password:
                self.debug(u'Master password found: {}'.format(master_password))
                return global_salt, master_password, entry_salt

        self.warning(u'No password has been found using the default list')
        return '', '', ''

    def remove_padding(self, data):
        """
        Remove PKCS#7 padding
        """
        try:
            nb = struct.unpack('B', data[-1])[0]  # Python 2
        except Exception:
            nb = data[-1]  # Python 3

        try:
            return data[:-nb]
        except Exception:
            self.debug(traceback.format_exc())
            return data

    def decrypt(self, key, iv, ciphertext):
        """
        Decrypt ciphered data (user / password) using the key previously found
        """
        data = triple_des(key, CBC, iv).decrypt(ciphertext)
        return self.remove_padding(data)

    def run(self):
        """
        Main function
        """
        # path = self.get_path(software_name)
        pwd_found = []
        self.path = self.path.format(**constant.profile)
        if os.path.exists(self.path):
            for profile in self.get_firefox_profiles(self.path):
                self.debug(u'Profile path found: {profile}'.format(profile=profile))

                credentials = self.get_login_data(profile)
                if credentials:
                    for key in self.get_key(profile):
                        for user, passw, url in credentials:
                            try:
                                pwd_found.append({
                                    'URL': url,
                                    'Login': self.decrypt(key=key, iv=user[1], ciphertext=user[2]).decode("utf-8"),
                                    'Password': self.decrypt(key=key, iv=passw[1], ciphertext=passw[2]).decode("utf-8"),
                                })
                            except Exception as e:
                                self.debug(u'An error occurred decrypting the password: {error}'.format(error=e))
                else:
                    self.info(u'Database empty')

        return pwd_found


# Name, path
firefox_browsers = [
    (u'firefox', u'{APPDATA}\\Mozilla\\Firefox'),
    (u'blackHawk', u'{APPDATA}\\NETGATE Technologies\\BlackHawk'),
    (u'cyberfox', u'{APPDATA}\\8pecxstudios\\Cyberfox'),
    (u'comodo IceDragon', u'{APPDATA}\\Comodo\\IceDragon'),
    (u'k-Meleon', u'{APPDATA}\\K-Meleon'),
    (u'icecat', u'{APPDATA}\\Mozilla\\icecat'),
]

firefox_browsers = [Mozilla(browser_name=name, path=path) for name, path in firefox_browsers]
