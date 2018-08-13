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

import copy
import struct
import utils
import platform
import ctypes, re, sys
import ctypes.util
import errno
import os
import signal
from .BaseProcess import BaseProcess, ProcessException
from .structures import *
import logging
import subprocess

logger = logging.getLogger('memorpy')

libc = ctypes.CDLL(ctypes.util.find_library('c'))

VM_REGION_BASIC_INFO_64    = 9

class vm_region_basic_info_64(ctypes.Structure):
    _fields_ = [
        ('protection',      ctypes.c_uint32),
        ('max_protection',  ctypes.c_uint32),
        ('inheritance',     ctypes.c_uint32),
        ('shared',          ctypes.c_uint32),
        ('reserved',        ctypes.c_uint32),
        ('offset',          ctypes.c_ulonglong),
        ('behavior',        ctypes.c_uint32),
        ('user_wired_count',ctypes.c_ushort),
]

VM_REGION_BASIC_INFO_COUNT_64 = ctypes.sizeof(vm_region_basic_info_64) / 4

VM_PROT_READ    = 1
VM_PROT_WRITE    = 2
VM_PROT_EXECUTE    = 4

class OSXProcess(BaseProcess):
    def __init__(self, pid=None, name=None, debug=True):
        """ Create and Open a process object from its pid or from its name """
        super(OSXProcess, self).__init__()
        if pid is not None:
            self.pid=pid
        elif name is not None:
            self.pid=OSXProcess.pid_from_name(name)
        else:
            raise ValueError("You need to instanciate process with at least a name or a pid")
        self.task=None
        self.mytask=None
        self._open()

    def close(self):
        pass

    def __del__(self):
        pass

    def _open(self):
        self.isProcessOpen = True
        self.task = ctypes.c_uint32()
        self.mytask=libc.mach_task_self()
        ret=libc.task_for_pid(self.mytask, ctypes.c_int(self.pid), ctypes.pointer(self.task))
        if ret!=0:
            raise ProcessException("task_for_pid failed with error code : %s"%ret)

    @staticmethod
    def list():
        #TODO list processes with ctypes
        processes=[]
        res=subprocess.check_output("ps A", shell=True)
        for line in res.split('\n'):
            try:
                tab=line.split()
                pid=int(tab[0])
                exe=' '.join(tab[4:])
                processes.append({"pid":int(pid), "name":exe})
            except:
                pass
        return processes

    @staticmethod
    def pid_from_name(name):
        for dic in OSXProcess.list():
            if name in dic['exe']:
                return dic['pid']


    def iter_region(self, start_offset=None, end_offset=None, protec=None, optimizations=None):
        """
            optimizations :
                i for inode==0 (no file mapping)
                s to avoid scanning shared regions
                x to avoid scanning x regions
                r don't scan ronly regions
        """
        maps = []
        address = ctypes.c_ulong(0)
        mapsize = ctypes.c_ulong(0)
        name    = ctypes.c_uint32(0)
        count   = ctypes.c_uint32(VM_REGION_BASIC_INFO_COUNT_64)
        info    = vm_region_basic_info_64()

        while True:
            r = libc.mach_vm_region(self.task, ctypes.pointer(address),
                                   ctypes.pointer(mapsize), VM_REGION_BASIC_INFO_64,
                                   ctypes.pointer(info), ctypes.pointer(count),
                                   ctypes.pointer(name))
            # If we get told "invalid address", we have crossed into kernel land...
            if r == 1:
                break

            if r != 0:
                raise ProcessException('mach_vm_region failed with error code %s' % r)
            if start_offset is not None:
                if address.value < start_offset:
                    address.value += mapsize.value
                    continue
            if end_offset is not None:
                if address.value > end_offset:
                    break
            p = info.protection
            if p & VM_PROT_EXECUTE:
                if optimizations and 'x' in optimizations:
                    address.value += mapsize.value
                    continue
            if info.shared:
                if optimizations and 's' in optimizations:
                    address.value += mapsize.value
                    continue
            if p & VM_PROT_READ:
                if not (p & VM_PROT_WRITE):
                    if optimizations and 'r' in optimizations:
                        address.value += mapsize.value
                        continue
                yield address.value, mapsize.value
            
            address.value += mapsize.value


    def write_bytes(self, address, data):
        raise NotImplementedError("write not implemented on OSX")
        return True

    def read_bytes(self, address, bytes = 4):
        pdata = ctypes.c_void_p(0)
        data_cnt = ctypes.c_uint32(0)
        
        ret = libc.mach_vm_read(self.task, ctypes.c_ulonglong(address), ctypes.c_longlong(bytes), ctypes.pointer(pdata), ctypes.pointer(data_cnt));
        #if ret==1:
        #    return ""
        if ret!=0:
            raise ProcessException("mach_vm_read returned : %s"%ret)
        buf=ctypes.string_at(pdata.value, data_cnt.value)
        libc.vm_deallocate(self.mytask, pdata, data_cnt)
        return buf


