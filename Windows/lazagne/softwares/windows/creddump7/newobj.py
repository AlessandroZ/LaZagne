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

from object import *
from types import regtypes as types
from operator import itemgetter
from struct import unpack

def get_ptr_type(structure, member):
    """Return the type a pointer points to.
       
       Arguments:
         structure : the name of the structure from vtypes
         member : a list of members

       Example:
         get_ptr_type('_EPROCESS', ['ActiveProcessLinks', 'Flink']) => ['_LIST_ENTRY']
    """
    if len(member) > 1:
        _, tp = get_obj_offset(types, [structure, member[0]])
        if tp == 'array':
            return types[structure][1][member[0]][1][2][1]
        else:
            return get_ptr_type(tp, member[1:])
    else:
        return types[structure][1][member[0]][1][1]

class Obj(object):
    """Base class for all objects.
       
       May return a subclass for certain data types to allow
       for special handling.
    """

    def __new__(typ, name, address, space):
        if name in globals():
            # This is a bit of "magic"
            # Could be replaced with a dict mapping type names to types
            return globals()[name](name,address,space)
        elif name in builtin_types:
            return Primitive(name, address, space)
        else:
            obj = object.__new__(typ)
            return obj
    
    def __init__(self, name, address, space):
        self.name = name
        self.address = address
        self.space = space

        # Subclasses can add fields to this list if they want them
        # to show up in values() or members(), even if they do not
        # appear in the vtype definition
        self.extra_members = []
    
    def __getattribute__(self, attr):
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            pass

        if self.name in builtin_types:
            raise AttributeError("Primitive types have no dynamic attributes")

        try:
            off, tp = get_obj_offset(types, [self.name, attr])
        except:
            raise AttributeError("'%s' has no attribute '%s'" % (self.name, attr))
        
        if tp == 'array':
            a_len = types[self.name][1][attr][1][1]
            l = []
            for i in range(a_len):
                a_off, a_tp = get_obj_offset(types, [self.name, attr, i])
                if a_tp == 'pointer':
                    ptp = get_ptr_type(self.name, [attr, i])
                    l.append(Pointer(a_tp, self.address+a_off, self.space, ptp))
                else:
                    l.append(Obj(a_tp, self.address+a_off, self.space))
            return l
        elif tp == 'pointer':
            # Can't just return a Obj here, since pointers need to also
            # know what type they point to.
            ptp = get_ptr_type(self.name, [attr])
            return Pointer(tp, self.address+off, self.space, ptp)
        else:
            return Obj(tp, self.address+off, self.space)
    
    def __div__(self, other):
        if isinstance(other,tuple) or isinstance(other,list):
            return Pointer(other[0], self.address, self.space, other[1])
        elif isinstance(other,str):
            return Obj(other, self.address, self.space)
        else:
            raise ValueError("Must provide a type name as string for casting")
    
    def members(self):
        """Return a list of this object's members, sorted by offset."""

        # Could also just return the list
        membs = [ (k, v[0]) for k,v in types[self.name][1].items()]
        membs.sort(key=itemgetter(1))
        return map(itemgetter(0),membs) + self.extra_members

    def values(self):
        """Return a dictionary of this object's members and their values"""
        
        valdict = {}
        for k in self.members():
            valdict[k] = getattr(self, k)
        return valdict

    def bytes(self, length=-1):
        """Get bytes starting at the address of this object.
        
           Arguments:
             length : the number of bytes to read. Default: size of
                this object.
        """

        if length == -1:
            length = self.size()
        return self.space.read(self.address, length)

    def size(self):
        """Get the size of this object."""

        if self.name in builtin_types:
            return builtin_types[self.name][0]
        else:
            return types[self.name][0]
    
    def __repr__(self):
        return "<%s @%08x>" % (self.name, self.address)

    def __eq__(self, other):
        if not isinstance(other, Obj):
            raise TypeError("Types are incomparable")
        return self.address == other.address and self.name == other.name

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.address) ^ hash(self.name)

    def is_valid(self):
        return self.space.is_valid_address(self.address)

    def get_offset(self, member):
        return get_obj_offset(types, [self.name] + member)

class Primitive(Obj):
    """Class to represent a primitive data type.
       
       Attributes:
         value : the python primitive value of this type
    """

    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def __init__(self, name, address, space):
        super(Primitive,self).__init__(name, address, space)
        length, fmt = builtin_types[name]
        data = space.read(address,length)
        if not data: self.value = None
        else: self.value = unpack(fmt,data)[0]
    
    def __repr__(self):
        return repr(self.value)

    def members(self):
        return []

class Pointer(Obj):
    """Class to represent pointers.
    
       value : the object pointed to

       If an attribute is not found in this instance,
       the attribute will be looked up in the referenced
       object."""

    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def __init__(self, name, address, space, ptr_type):
        super(Pointer,self).__init__(name, address, space)
        ptr_address = read_value(space, name, address)
        if ptr_type[0] == 'pointer':
            self.value = Pointer(ptr_type[0], ptr_address, self.space, ptr_type[1])
        else:
            self.value = Obj(ptr_type[0], ptr_address, self.space)
    
    def __getattribute__(self, attr):
        # It's still nice to be able to access things through pointers
        # without having to explicitly dereference them, so if we don't
        # find an attribute via our superclass, just dereference the pointer
        # and return the attribute in the pointed-to type.
        try:
            return super(Pointer,self).__getattribute__(attr)
        except AttributeError:
            return getattr(self.value, attr)
    
    def __repr__(self):
        return "<pointer to [%s @%08x]>" % (self.value.name, self.value.address)

    def members(self):
        return self.value.members()

class _UNICODE_STRING(Obj):
    """Class representing a _UNICODE_STRING

    Adds the following behavior:
      * The Buffer attribute is presented as a Python string rather
        than a pointer to an unsigned short.
      * The __str__ method returns the value of the Buffer.
    """

    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def __str__(self):
        return self.Buffer

    # Custom Attributes
    def getBuffer(self):
        return read_unicode_string(self.space, types, [], self.address)
    Buffer = property(fget=getBuffer)

class _CM_KEY_NODE(Obj):
    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def getName(self):
        return read_string(self.space, types, ['_CM_KEY_NODE', 'Name'],
            self.address, self.NameLength.value)
    Name = property(fget=getName)

class _CM_KEY_VALUE(Obj):
    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def getName(self):
        return read_string(self.space, types, ['_CM_KEY_VALUE', 'Name'],
            self.address, self.NameLength.value)
    Name = property(fget=getName)

class _CHILD_LIST(Obj):
    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def getList(self):
        lst = []
        list_address = read_obj(self.space, types,
            ['_CHILD_LIST', 'List'], self.address)
        for i in range(self.Count.value):
            lst.append(Pointer("pointer", list_address+(i*4), self.space,
                ["_CM_KEY_VALUE"]))
        return lst
    List = property(fget=getList)

class _CM_KEY_INDEX(Obj):
    def __new__(typ, *args, **kwargs):
        obj = object.__new__(typ)
        return obj

    def getList(self):
        lst = []
        for i in range(self.Count.value):
            # we are ignoring the hash value here
            off,tp = get_obj_offset(types, ['_CM_KEY_INDEX', 'List', i*2])
            lst.append(Pointer("pointer", self.address+off, self.space,
                ["_CM_KEY_NODE"]))
        return lst
    List = property(fget=getList)
