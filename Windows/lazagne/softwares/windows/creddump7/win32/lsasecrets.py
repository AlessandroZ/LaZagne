# This file is part of creddump.
#
# creddump is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# creddump is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with creddump.  If not, see <http://www.gnu.org/licenses/>.

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

import hashlib
import os

from .rawreg import *
from ..addrspace import HiveFileAddressSpace
from .hashdump import get_bootkey, str_to_key
from lazagne.config.crypto.rc4 import RC4
from lazagne.config.crypto.pyDes import des, ECB
from lazagne.config.crypto.pyaes.aes import AESModeOfOperationCBC


def get_lsa_key(secaddr, bootkey, vista):
    root = get_root(secaddr)
    if not root:
        return None

    if vista:
        enc_reg_key = open_key(root, [b"Policy", b"PolEKList"])
    else:
        enc_reg_key = open_key(root, [b"Policy", b"PolSecretEncryptionKey"])

    if not enc_reg_key:
        return None

    enc_reg_value = enc_reg_key.ValueList.List[0]
    if not enc_reg_value:
        return None

    obf_lsa_key = secaddr.read(enc_reg_value.Data.value, enc_reg_value.DataLength.value)
    if not obf_lsa_key:
        return None

    if not vista:
        md5 = hashlib.md5()
        md5.update(bootkey)
        for i in range(1000):
            md5.update(obf_lsa_key[60:76])
        rc4key = md5.digest()
        rc4 = RC4(rc4key)
        lsa_key = rc4.encrypt(obf_lsa_key[12:60])
        lsa_key = lsa_key[0x10:0x20]
    else:
        lsa_key = decrypt_aes(obf_lsa_key, bootkey)
        lsa_key = lsa_key[68:100]

    return lsa_key


def decrypt_secret(secret, key):
    """Python implementation of SystemFunction005.

    Decrypts a block of data with DES using given key.
    Note that key can be longer than 7 bytes."""
    decrypted_data = b''
    j = 0  # key index
    for i in range(0, len(secret), 8):
        enc_block = secret[i:i + 8]
        block_key = key[j:j + 7]
        des_key = str_to_key(block_key)
        crypter = des(des_key, ECB)

        try:
            decrypted_data += crypter.decrypt(enc_block)
        except Exception:
            continue

        j += 7
        if len(key[j:j + 7]) < 7:
            j = len(key[j:j + 7])

    (dec_data_len,) = unpack("<L", decrypted_data[:4])
    return decrypted_data[8:8 + dec_data_len]


def decrypt_aes(secret, key):
    sha = hashlib.sha256()
    sha.update(key)
    for _i in range(1, 1000 + 1):
        sha.update(secret[28:60])
    aeskey = sha.digest()

    data = b""
    for i in range(60, len(secret), 16):
        aes = AESModeOfOperationCBC(aeskey, iv=b"\x00" * 16)
        buf = secret[i: i + 16]
        if len(buf) < 16:
            buf += (16 - len(buf)) * b"\00"

        data += aes.decrypt(buf)

    return data


def get_secret_by_name(secaddr, name, lsakey, vista):
    root = get_root(secaddr)
    if not root:
        return None

    if isinstance(name, str):
        name = name.encode()

    enc_secret_key = open_key(root, [b"Policy", b"Secrets", name, b"CurrVal"])
    if not enc_secret_key:
        return None

    enc_secret_value = enc_secret_key.ValueList.List[0]
    if not enc_secret_value:
        return None

    enc_secret = secaddr.read(enc_secret_value.Data.value, enc_secret_value.DataLength.value)
    if not enc_secret:
        return None

    if vista:
        secret = decrypt_aes(enc_secret, lsakey)
    else:
        secret = decrypt_secret(enc_secret[0xC:], lsakey)

    return secret


def get_secrets(sysaddr, secaddr, vista):
    root = get_root(secaddr)
    if not root:
        return None

    bootkey = get_bootkey(sysaddr)
    lsakey = get_lsa_key(secaddr, bootkey, vista)

    secrets_key = open_key(root, [b"Policy", b"Secrets"])
    if not secrets_key:
        return None

    secrets = {}
    for key in subkeys(secrets_key):
        sec_val_key = open_key(key, [b"CurrVal"])
        if not sec_val_key:
            continue

        enc_secret_value = sec_val_key.ValueList.List[0]
        if not enc_secret_value:
            continue

        enc_secret = secaddr.read(enc_secret_value.Data.value, enc_secret_value.DataLength.value)
        if not enc_secret:
            continue

        if vista:
            secret = decrypt_aes(enc_secret, lsakey)
        else:
            secret = decrypt_secret(enc_secret[0xC:], lsakey)

        secrets[key.Name] = secret

    return secrets


def get_file_secrets(sysfile, secfile, vista):
    if not os.path.isfile(sysfile) or not os.path.isfile(secfile):
        return

    sysaddr = HiveFileAddressSpace(sysfile)
    secaddr = HiveFileAddressSpace(secfile)

    return get_secrets(sysaddr, secaddr, vista)
