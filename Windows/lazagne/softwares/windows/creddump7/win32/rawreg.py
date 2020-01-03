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

from ..newobj import Obj, Pointer
from struct import unpack

ROOT_INDEX = 0x20
LH_SIG = unpack("<H", b"lh")[0]
LF_SIG = unpack("<H", b"lf")[0]
RI_SIG = unpack("<H", b"ri")[0]


def get_root(address_space):
    return Obj("_CM_KEY_NODE", ROOT_INDEX, address_space)


def open_key(root, key):
    if not key:
        return root
    
    keyname = key.pop(0)
    if isinstance(keyname, str):
        keyname = keyname.encode()

    for s in subkeys(root):
        if s.Name.upper() == keyname.upper():
            return open_key(s, key)
    # print "ERR: Couldn't find subkey %s of %s" % (keyname, root.Name)
    return None


def subkeys(key, stable=True):
    if stable:
        k = 0
    else:
        k = 1

    sk = (key.SubKeyLists[k]/["pointer", ["_CM_KEY_INDEX"]]).value
    sub_list = []
    if (sk.Signature.value == LH_SIG or
            sk.Signature.value == LF_SIG):
        sub_list = sk.List
    elif sk.Signature.value == RI_SIG:
        lfs = []
        for i in range(sk.Count.value):
            off, tp = sk.get_offset(['List', i])
            lfs.append(Pointer("pointer", sk.address+off, sk.space,
                ["_CM_KEY_INDEX"]))
        for lf in lfs:
            sub_list += lf.List

    for s in sub_list:
        if s.is_valid() and s.Signature.value == 27502:
            yield s.value


def values(key):
    for v in key.ValueList.List:
        yield v.value


def walk(root):
    for k in subkeys(root):
        yield k
        for j in walk(k):
            yield j
