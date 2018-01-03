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
from __future__ import absolute_import

from .rawreg import *
from ..addrspace import HiveFileAddressSpace
from Crypto.Hash import MD5
from Crypto.Cipher import ARC4,DES
from struct import unpack,pack

odd_parity = [
  1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
  16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
  32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
  49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
  64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
  81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
  97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
  112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
  128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
  145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
  161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
  176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
  193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
  208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
  224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
  241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
]

# Permutation matrix for boot key
p = [ 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
      0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 ]

# Constants for SAM decrypt algorithm
aqwerty = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
anum = "0123456789012345678901234567890123456789\0"
antpassword = "NTPASSWORD\0"
almpassword = "LMPASSWORD\0"

empty_lm = "aad3b435b51404eeaad3b435b51404ee".decode('hex')
empty_nt = "31d6cfe0d16ae931b73c59d7e0c089c0".decode('hex')

def str_to_key(s):
    key = []
    key.append( ord(s[0])>>1 )
    key.append( ((ord(s[0])&0x01)<<6) | (ord(s[1])>>2) )
    key.append( ((ord(s[1])&0x03)<<5) | (ord(s[2])>>3) )
    key.append( ((ord(s[2])&0x07)<<4) | (ord(s[3])>>4) )
    key.append( ((ord(s[3])&0x0F)<<3) | (ord(s[4])>>5) )
    key.append( ((ord(s[4])&0x1F)<<2) | (ord(s[5])>>6) )
    key.append( ((ord(s[5])&0x3F)<<1) | (ord(s[6])>>7) )
    key.append( ord(s[6])&0x7F )
    for i in range(8):
        key[i] = (key[i]<<1)
        key[i] = odd_parity[key[i]]
    return "".join(chr(k) for k in key)

def sid_to_key(sid):
    s1 = ""
    s1 += chr(sid & 0xFF)
    s1 += chr((sid>>8) & 0xFF)
    s1 += chr((sid>>16) & 0xFF)
    s1 += chr((sid>>24) & 0xFF)
    s1 += s1[0];
    s1 += s1[1];
    s1 += s1[2];
    s2 = s1[3] + s1[0] + s1[1] + s1[2]
    s2 += s2[0] + s2[1] + s2[2]

    return str_to_key(s1),str_to_key(s2)
    
def find_control_set(sysaddr):
    root = get_root(sysaddr)
    if not root:
        return 1

    csselect = open_key(root, ["Select"])
    if not csselect:
        return 1

    for v in values(csselect):
        if v.Name == "Current": return v.Data.value

def get_bootkey(sysaddr):
    cs = find_control_set(sysaddr)
    lsa_base = ["ControlSet%03d" % cs, "Control", "Lsa"]
    lsa_keys = ["JD","Skew1","GBG","Data"]

    root = get_root(sysaddr)
    if not root: return None

    lsa = open_key(root, lsa_base)
    if not lsa: return None

    bootkey = ""
    
    for lk in lsa_keys:
        key = open_key(lsa, [lk])
        class_data = sysaddr.read(key.Class.value, key.ClassLength.value)
        bootkey += class_data.decode('utf-16-le').decode('hex')
    
    bootkey_scrambled = ""
    for i in range(len(bootkey)):
        bootkey_scrambled += bootkey[p[i]]
    
    return bootkey_scrambled

def get_hbootkey(samaddr, bootkey):
    sam_account_path = ["SAM", "Domains", "Account"]

    root = get_root(samaddr)
    if not root: return None

    sam_account_key = open_key(root, sam_account_path)
    if not sam_account_key: return None

    F = None
    for v in values(sam_account_key):
        if v.Name == 'F':
            F = samaddr.read(v.Data.value, v.DataLength.value)
    if not F: return None

    md5 = MD5.new()
    md5.update(F[0x70:0x80] + aqwerty + bootkey + anum)
    rc4_key = md5.digest()

    rc4 = ARC4.new(rc4_key)
    hbootkey = rc4.encrypt(F[0x80:0xA0])
    
    return hbootkey

def get_user_keys(samaddr):
    user_key_path = ["SAM", "Domains", "Account", "Users"]

    root = get_root(samaddr)
    if not root: return []

    user_key = open_key(root, user_key_path)
    if not user_key: return []

    return [k for k in subkeys(user_key) if k.Name != "Names"]

def decrypt_single_hash(rid, hbootkey, enc_hash, lmntstr):
    (des_k1,des_k2) = sid_to_key(rid)
    d1 = DES.new(des_k1, DES.MODE_ECB)
    d2 = DES.new(des_k2, DES.MODE_ECB)

    md5 = MD5.new()
    md5.update(hbootkey[:0x10] + pack("<L",rid) + lmntstr)
    rc4_key = md5.digest()
    rc4 = ARC4.new(rc4_key)
    obfkey = rc4.encrypt(enc_hash)
    hash = d1.decrypt(obfkey[:8]) + d2.decrypt(obfkey[8:])

    return hash

def decrypt_hashes(rid, enc_lm_hash, enc_nt_hash, hbootkey):
    # LM Hash
    if enc_lm_hash:
        lmhash = decrypt_single_hash(rid, hbootkey, enc_lm_hash, almpassword)
    else:
        lmhash = ""
    
    # NT Hash
    if enc_nt_hash:
        nthash = decrypt_single_hash(rid, hbootkey, enc_nt_hash, antpassword)
    else:
        nthash = ""

    return lmhash,nthash

def get_user_hashes(user_key, hbootkey):
    samaddr = user_key.space
    rid = int(user_key.Name, 16)
    V = None
    for v in values(user_key):
        if v.Name == 'V':
            V = samaddr.read(v.Data.value, v.DataLength.value)
    if not V: return None

    hash_offset = unpack("<L", V[0x9c:0x9c+4])[0] + 0xCC

    lm_exists = True if unpack("<L", V[0x9c+4:0x9c+8])[0] == 20 else False
    nt_exists = True if unpack("<L", V[0x9c+16:0x9c+20])[0] == 20 else False

    enc_lm_hash = V[hash_offset+4:hash_offset+20] if lm_exists else ""
    enc_nt_hash = V[hash_offset+(24 if lm_exists else 8):hash_offset+(24 if lm_exists else 8)+16] if nt_exists else ""

    return decrypt_hashes(rid, enc_lm_hash, enc_nt_hash, hbootkey)

def get_user_name(user_key):
    samaddr = user_key.space
    V = None
    for v in values(user_key):
        if v.Name == 'V':
            V = samaddr.read(v.Data.value, v.DataLength.value)
    if not V: return None

    name_offset = unpack("<L", V[0x0c:0x10])[0] + 0xCC
    name_length = unpack("<L", V[0x10:0x14])[0]

    username = V[name_offset:name_offset+name_length].decode('utf-16-le')
    return username

def dump_hashes(sysaddr, samaddr):
    bootkey = get_bootkey(sysaddr)
    hbootkey = get_hbootkey(samaddr,bootkey)
    results = []
    for user in get_user_keys(samaddr):
        lmhash,nthash = get_user_hashes(user,hbootkey)
        if not lmhash: lmhash = empty_lm
        if not nthash: nthash = empty_nt
        results.append("%s:%d:%s:%s:::" % (get_user_name(user), int(user.Name,16), lmhash.encode('hex'), nthash.encode('hex')))
    return results

def dump_file_hashes(syshive_fname, samhive_fname):
    sysaddr = HiveFileAddressSpace(syshive_fname)
    samaddr = HiveFileAddressSpace(samhive_fname)
    return dump_hashes(sysaddr, samaddr)
