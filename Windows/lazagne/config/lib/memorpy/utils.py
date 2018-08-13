# Author: Nicolas VERDIER
# This file is part of memorpy.
#
# memorpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# memorpy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with memorpy.  If not, see <http://www.gnu.org/licenses/>.

import re
import struct

def re_to_unicode(s):
    newstring = ''
    for c in s:
        newstring += re.escape(c) + '\\x00'

    return newstring


def type_unpack(type):
    """ return the struct and the len of a particular type """
    type = type.lower()
    s = None
    l = None
    if type == 'short':
        s = 'h'
        l = 2
    elif type == 'ushort':
        s = 'H'
        l = 2
    elif type == 'int':
        s = 'i'
        l = 4
    elif type == 'uint':
        s = 'I'
        l = 4
    elif type == 'long':
        s = 'l'
        l = 4
    elif type == 'ulong':
        s = 'L'
        l = 4
    elif type == 'float':
        s = 'f'
        l = 4
    elif type == 'double':
        s = 'd'
        l = 8
    else:
        raise TypeError('Unknown type %s' % type)
    return ('<' + s, l)


def hex_dump(data, addr = 0, prefix = '', ftype = 'bytes'):
    """
    function originally from pydbg, modified to display other types
    """
    dump = prefix
    slice = ''
    if ftype != 'bytes':
        structtype, structlen = type_unpack(ftype)
        for i in range(0, len(data), structlen):
            if addr % 16 == 0:
                dump += ' '
                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += '.'

                dump += '\n%s%08X: ' % (prefix, addr)
                slice = ''
            tmpval = 'NaN'
            try:
                packedval = data[i:i + structlen]
                tmpval = struct.unpack(structtype, packedval)[0]
            except Exception as e:
                print(e)

            if tmpval == 'NaN':
                dump += '{:<15} '.format(tmpval)
            elif ftype == 'float':
                dump += '{:<15.4f} '.format(tmpval)
            else:
                dump += '{:<15} '.format(tmpval)
            addr += structlen

    else:
        for byte in data:
            if addr % 16 == 0:
                dump += ' '
                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += '.'

                dump += '\n%s%08X: ' % (prefix, addr)
                slice = ''
            dump += '%02X ' % byte
            slice += chr(byte)
            addr += 1

    remainder = addr % 16
    if remainder != 0:
        dump += '   ' * (16 - remainder) + ' '
    for char in slice:
        if ord(char) >= 32 and ord(char) <= 126:
            dump += char
        else:
            dump += '.'

    return dump + '\n'
