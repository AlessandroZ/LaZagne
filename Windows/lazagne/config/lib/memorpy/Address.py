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

from .utils import *

class AddressException(Exception):
    pass


class Address(object):
    """ this class is used to have better representation of memory addresses """

    def __init__(self, value, process, default_type = 'uint'):
        self.value = int(value)
        self.process = process
        self.default_type = default_type
        self.symbolic_name = None

    def read(self, type = None, maxlen = None, errors='raise'):
        if maxlen is None:
            try:
                int(type)
                maxlen = int(type)
                type = None
            except:
                pass

        if not type:
            type = self.default_type
        if not maxlen:
            return self.process.read(self.value, type=type, errors=errors)
        else:
            return self.process.read(self.value, type=type, maxlen=maxlen, errors=errors)

    def write(self, data, type = None):
        if not type:
            type = self.default_type
        return self.process.write(self.value, data, type=type)

    def symbol(self):
        return self.process.get_symbolic_name(self.value)

    def get_instruction(self):
        return self.process.get_instruction(self.value)

    def dump(self, ftype = 'bytes', size = 512, before = 32):
        buf = self.process.read_bytes(self.value - before, size)
        print(hex_dump(buf, self.value - before, ftype=ftype))

    def __nonzero__(self):
        return self.value is not None and self.value != 0

    def __add__(self, other):
        return Address(self.value + int(other), self.process, self.default_type)

    def __sub__(self, other):
        return Address(self.value - int(other), self.process, self.default_type)

    def __repr__(self):
        if not self.symbolic_name:
            self.symbolic_name = self.symbol()
        return str('<Addr: %s' % self.symbolic_name + '>')

    def __str__(self):
        if not self.symbolic_name:
            self.symbolic_name = self.symbol()
        return str('<Addr: %s' % self.symbolic_name + ' : "%s" (%s)>' % (str(self.read()).encode('unicode_escape'), self.default_type))

    def __int__(self):
        return int(self.value)

    def __hex__(self):
        return hex(self.value)

    def __get__(self, instance, owner):
        return self.value

    def __set__(self, instance, value):
        self.value = int(value)

    def __lt__(self, other):
        return self.value < int(other)

    def __le__(self, other):
        return self.value <= int(other)

    def __eq__(self, other):
        return self.value == int(other)

    def __ne__(self, other):
        return self.value != int(other)

    def __gt__(self, other):
        return self.value > int(other)

    def __ge__(self, other):
        return self.value >= int(other)

