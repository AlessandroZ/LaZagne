#!/usr/bin/python

# A simple implementation of pbkdf2 using stock python modules. See RFC2898
# for details. Basically, it derives a key from a password and salt.

# (c) 2004 Matt Johnston <matt @ ucc asn au>
# This code may be freely used and modified for any purpose.

import hmac
import hashlib
import sys

from struct import pack

BLOCKLEN = 20


def char_to_int(string):
    if sys.version_info[0] == 2 or isinstance(string, str):
        return ord(string)
    else:
        return string  # Python 3

def chr_or_byte(integer):
    if sys.version_info[0] == 2:
        return chr(integer)
    else:
        return bytes([integer])  # Python 3


# this is what you want to call.
def pbkdf2(password, salt, itercount, keylen):
    # l - number of output blocks to produce
    l = keylen / BLOCKLEN
    if keylen % BLOCKLEN != 0:
        l += 1

    h = hmac.new(password, None, hashlib.sha1)

    T = b''
    for i in range(1, int(l) + 1):
        T += pbkdf2_F(h, salt, itercount, i)

    return T[: -(BLOCKLEN - keylen % BLOCKLEN)]


def xorstr(a, b):
    if len(a) != len(b):
        raise "xorstr(): lengths differ"

    ret = b''
    for i in range(len(a)):
        ret += chr_or_byte(char_to_int(a[i]) ^ char_to_int(b[i]))

    return ret


def prf(h, data):
    hm = h.copy()
    hm.update(data)
    return hm.digest()


# Helper as per the spec. h is a hmac which has been created seeded with the
# password, it will be copy()ed and not modified.
def pbkdf2_F(h, salt, itercount, blocknum):
    U = prf(h, salt + pack('>i', blocknum))
    T = U

    for i in range(2, itercount + 1):
        U = prf(h, U)
        T = xorstr(T, U)

    return T
