#!/usr/bin/env python
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.            ##
## This document is the property of Cassidian SAS, it may not be copied or ##
## circulated without prior licence                                        ##
##                                                                         ##
##  Author: Jean-Michel Picod <jmichel.p@gmail.com>                        ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

import struct


class Eater(object):
    """This class is a helper for parsing binary structures."""

    def __init__(self, raw, offset=0, end=None, endianness="<"):
        self.raw = raw
        self.ofs = offset
        if end is None:
            end = len(raw)
        self.end = end
        self.endianness = endianness

    def prepare_fmt(self, fmt):
        """Internal use. Prepend endianness to the given format if it is not
        already specified.

        fmt is a format string for struct.unpack()

        Returns a tuple of the format string and the corresponding data size.

        """
        if fmt[0] not in ["<", ">", "!", "@"]:
            fmt = self.endianness+fmt
        return fmt, struct.calcsize(fmt)

    def read(self, fmt):
        """Parses data with the given format string without taking away bytes.
        
        Returns an array of elements or just one element depending on fmt.

        """
        fmt, sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        if len(v) == 1:
            v = v[0]
        return v

    def eat(self, fmt):
        """Parses data with the given format string.
        
        Returns an array of elements or just one element depending on fmt.

        """
        fmt, sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        if len(v) == 1:
            v = v[0]
        self.ofs += sz
        return v

    def eat_string(self, length):
        """Eats and returns a string of length characters"""
        return self.eat("%us" % length)

    def eat_length_and_string(self, fmt):
        """Eats and returns a string which length is obtained after eating
        an integer represented by fmt

        """
        l = self.eat(fmt)
        return self.eat_string(l)

    def pop(self, fmt):
        """Eats a structure represented by fmt from the end of raw data"""
        fmt, sz = self.prepare_fmt(fmt)
        self.end -= sz
        v = struct.unpack_from(fmt, self.raw, self.end)
        if len(v) == 1:
            v = v[0]
        return v

    def pop_string(self, length):
        """Pops and returns a string of length characters"""
        return self.pop("%us" % length)

    def pop_length_and_string(self, fmt):
        """Pops and returns a string which length is obtained after poping an
        integer represented by fmt.

        """
        l = self.pop(fmt)
        return self.pop_string(l)
    
    def remain(self):
        """Returns all the bytes that have not been eated nor poped yet."""
        return self.raw[self.ofs:self.end]

    def eat_sub(self, length):
        """Eats a sub-structure that is contained in the next length bytes"""
        sub = self.__class__(self.raw[self.ofs:self.ofs+length], endianness=self.endianness)
        self.ofs += length
        return sub

    def __nonzero__(self):
        return self.ofs < self.end


class DataStruct(object):
    """Don't use this class unless you know what you are doing!"""

    def __init__(self, raw=None):
        if raw is not None:
            self.parse(Eater(raw, endianness="<"))

    def parse(self, eater_obj):
        raise NotImplementedError("This function must be implemented in subclasses")

