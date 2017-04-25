# Volatility
# Copyright (C) 2007 Volatile Systems
#
# Original Source:
# Copyright (C) 2004,2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

""" Alias for all address spaces """

import os
import struct

class FileAddressSpace:
    def __init__(self, fname, mode='rb', fast=False):
        self.fname = fname
	self.name = fname
	self.fhandle = open(fname, mode)
        self.fsize = os.path.getsize(fname)

	if fast == True:
            self.fast_fhandle = open(fname, mode)

    def fread(self,len):
        return self.fast_fhandle.read(len)

    def read(self, addr, len):
        self.fhandle.seek(addr)        
        return self.fhandle.read(len)    

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval, ) =  struct.unpack('L', string)
        return longval

    def get_address_range(self):
        return [0,self.fsize-1]

    def get_available_addresses(self):
        return [self.get_address_range()]

    def is_valid_address(self, addr):
        return addr < self.fsize - 1

    def close():
        self.fhandle.close()

# Code below written by Brendan Dolan-Gavitt

BLOCK_SIZE = 0x1000

class HiveFileAddressSpace:
    def __init__(self, fname):
        self.fname = fname
        self.base = FileAddressSpace(fname)

    def vtop(self, vaddr):
        return vaddr + BLOCK_SIZE + 4

    def read(self, vaddr, length, zero=False):
        first_block = BLOCK_SIZE - vaddr % BLOCK_SIZE
        full_blocks = ((length + (vaddr % BLOCK_SIZE)) / BLOCK_SIZE) - 1
        left_over = (length + vaddr) % BLOCK_SIZE
        
        paddr = self.vtop(vaddr)
        if paddr == None and zero:
            if length < first_block:
                return "\0" * length
            else:
                stuff_read = "\0" * first_block
        elif paddr == None:
            return None
        else:
            if length < first_block:
                stuff_read = self.base.read(paddr, length)
                if not stuff_read and zero:
                    return "\0" * length
                else:
                    return stuff_read

            stuff_read = self.base.read(paddr, first_block)
            if not stuff_read and zero:
                stuff_read = "\0" * first_block

        new_vaddr = vaddr + first_block
        for i in range(0,full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * BLOCK_SIZE
            elif paddr == None:
                return None
            else:
                new_stuff = self.base.read(paddr, BLOCK_SIZE)
                if not new_stuff and zero:
                    new_stuff = "\0" * BLOCK_SIZE
                elif not new_stuff:
                    return None
                else:
                    stuff_read = stuff_read + new_stuff
            new_vaddr = new_vaddr + BLOCK_SIZE

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None and zero:
                stuff_read = stuff_read + "\0" * left_over
            elif paddr == None:
                return None
            else:
                stuff_read = stuff_read + self.base.read(paddr, left_over)
        return stuff_read

    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
        (longval, ) =  struct.unpack('L', string)
        return longval

    def is_valid_address(self, vaddr):
        paddr = self.vtop(vaddr)
        if not paddr: return False
        return self.base.is_valid_address(paddr)
