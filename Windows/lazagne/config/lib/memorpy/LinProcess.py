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
# import utils
import platform
import ctypes, re, sys
from ctypes import create_string_buffer, byref, c_int, c_void_p, c_long, c_size_t, c_ssize_t, POINTER, get_errno
import errno
import os
import signal
from .BaseProcess import BaseProcess, ProcessException
from .structures import *
import logging

logger = logging.getLogger('memorpy')

libc=ctypes.CDLL("libc.so.6", use_errno=True)
get_errno_loc = libc.__errno_location
get_errno_loc.restype = POINTER(c_int)

def errcheck(ret, func, args):
    if ret == -1:
        _errno = get_errno() or errno.EPERM
        raise OSError(os.strerror(_errno))
    return ret

c_ptrace = libc.ptrace
c_pid_t = ctypes.c_int32 # This assumes pid_t is int32_t
c_ptrace.argtypes = [c_int, c_pid_t, c_void_p, c_void_p]
c_ptrace.restype = c_long
mprotect = libc.mprotect
mprotect.restype = c_int
mprotect.argtypes = [c_void_p, c_size_t, c_int]
LARGE_FILE_SUPPORT=False
try:
    c_off64_t=ctypes.c_longlong
    lseek64 = libc.lseek64
    lseek64.argtypes = [c_int, c_off64_t, c_int]
    lseek64.errcheck=errcheck
    open64 = libc.open64
    open64.restype = c_int
    open64.argtypes = [c_void_p, c_int]
    open64.errcheck=errcheck
    pread64=libc.pread64
    pread64.argtypes = [c_int, c_void_p, c_size_t, c_off64_t]
    pread64.restype = c_ssize_t
    pread64.errcheck=errcheck
    c_close=libc.close
    c_close.argtypes = [c_int]
    c_close.restype = c_int
    LARGE_FILE_SUPPORT=True
except:
    logger.warning("no Large File Support")

class LinProcess(BaseProcess):
    def __init__(self, pid=None, name=None, debug=True, ptrace=None):
        """ Create and Open a process object from its pid or from its name """
        super(LinProcess, self).__init__()
        self.mem_file=None
        self.ptrace_started=False
        if pid is not None:
            self.pid=pid
        elif name is not None:
            self.pid=LinProcess.pid_from_name(name)
        else:
            raise ValueError("You need to instanciate process with at least a name or a pid")
        if ptrace is None:
            if os.getuid()==0:
                self.read_ptrace=False # no need to ptrace the process when root to read memory
            else:
                self.read_ptrace=True
        self._open()

    def check_ptrace_scope(self):
        """ check ptrace scope and raise an exception if privileges are unsufficient

        The sysctl settings (writable only with CAP_SYS_PTRACE) are:

        0 - classic ptrace permissions: a process can PTRACE_ATTACH to any other
            process running under the same uid, as long as it is dumpable (i.e.
            did not transition uids, start privileged, or have called
            prctl(PR_SET_DUMPABLE...) already). Similarly, PTRACE_TRACEME is
            unchanged.

        1 - restricted ptrace: a process must have a predefined relationship
            with the inferior it wants to call PTRACE_ATTACH on. By default,
            this relationship is that of only its descendants when the above
            classic criteria is also met. To change the relationship, an
            inferior can call prctl(PR_SET_PTRACER, debugger, ...) to declare
            an allowed debugger PID to call PTRACE_ATTACH on the inferior.
            Using PTRACE_TRACEME is unchanged.

        2 - admin-only attach: only processes with CAP_SYS_PTRACE may use ptrace
            with PTRACE_ATTACH, or through children calling PTRACE_TRACEME.

        3 - no attach: no processes may use ptrace with PTRACE_ATTACH nor via
            PTRACE_TRACEME. Once set, this sysctl value cannot be changed.
        """
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope",'rb') as f:
                ptrace_scope=int(f.read().strip())
            if ptrace_scope==3:
                logger.warning("yama/ptrace_scope == 3 (no attach). :/")
            if os.getuid()==0:
                return
            elif ptrace_scope == 1:
                logger.warning("yama/ptrace_scope == 1 (restricted). you can't ptrace other process ... get root")
            elif ptrace_scope == 2:
                logger.warning("yama/ptrace_scope == 2 (admin-only). Warning: check you have CAP_SYS_PTRACE")

        except IOError:
            pass

        except Exception as e:
            logger.warning("Error getting ptrace_scope ?? : %s"%e)

    def close(self):
        if self.mem_file:
            if not LARGE_FILE_SUPPORT:
                self.mem_file.close()
            else:
                c_close(self.mem_file)
            self.mem_file=None
        if self.ptrace_started:
            self.ptrace_detach()

    def __del__(self):
        self.close()

    def _open(self):
        self.isProcessOpen = True
        self.check_ptrace_scope()
        if os.getuid()!=0:
            #to raise an exception if ptrace is not allowed
            self.ptrace_attach()
            self.ptrace_detach()

        #open file descriptor
        if not LARGE_FILE_SUPPORT:
            self.mem_file=open("/proc/" + str(self.pid) + "/mem", 'rb', 0)
        else:
            path=create_string_buffer(b"/proc/%d/mem" % self.pid)
            self.mem_file=open64(byref(path), os.O_RDONLY)

    @staticmethod
    def list():
        processes=[]
        for pid in os.listdir("/proc"):
            try:
                exe=os.readlink("/proc/%s/exe"%pid)
                processes.append({"pid":int(pid), "name":exe})
            except:
                pass
        return processes

    @staticmethod
    def pid_from_name(name):
        #quick and dirty, works with all linux not depending on ps output
        for pid in os.listdir("/proc"):
            try:
                int(pid)
            except:
                continue
            pname=""
            with open("/proc/%s/cmdline"%pid,'r') as f:
                pname=f.read()
            if name in pname:
                return int(pid)
        raise ProcessException("No process with such name: %s"%name)

    ## Partial interface to ptrace(2), only for PTRACE_ATTACH and PTRACE_DETACH.
    def _ptrace(self, attach):
        op = ctypes.c_int(PTRACE_ATTACH if attach else PTRACE_DETACH)
        c_pid = c_pid_t(self.pid)
        null = ctypes.c_void_p()

        if not attach:
            os.kill(self.pid, signal.SIGSTOP)
            os.waitpid(self.pid, 0)

        err = c_ptrace(op, c_pid, null, null)

        if not attach:
            os.kill(self.pid, signal.SIGCONT)

        if err != 0:
            raise OSError("%s: %s"%(
                'PTRACE_ATTACH' if attach else 'PTRACE_DETACH',
                errno.errorcode.get(ctypes.get_errno(), 'UNKNOWN')
            ))

    def iter_region(self, start_offset=None, end_offset=None, protec=None, optimizations=None):
        """
            optimizations :
                i for inode==0 (no file mapping)
                s to avoid scanning shared regions
                x to avoid scanning x regions
                r don't scan ronly regions
        """
        with open("/proc/" + str(self.pid) + "/maps", 'r') as maps_file:
            for line in maps_file:
                m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+)\s+([-rwpsx]+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+:[0-9A-Fa-f]+)\s+([0-9]+)\s*(.*)', line)
                if not m:
                    continue
                start, end, region_protec, offset, dev, inode, pathname = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4), m.group(5), int(m.group(6)), m.group(7)
                if start_offset is not None:
                    if start < start_offset:
                        continue
                if end_offset is not None:
                    if start > end_offset:
                        continue
                chunk=end-start
                if 'r' in region_protec: # TODO: handle protec parameter
                    if optimizations:
                        if 'i' in optimizations and inode != 0:
                            continue
                        if 's' in optimizations and 's' in region_protec:
                            continue
                        if 'x' in optimizations and 'x' in region_protec:
                            continue
                        if 'r' in optimizations and not 'w' in region_protec:
                            continue
                    yield start, chunk

    def ptrace_attach(self):
        if not self.ptrace_started:
            res=self._ptrace(True)
            self.ptrace_started=True
        return res

    def ptrace_detach(self):
        if self.ptrace_started:
            res=self._ptrace(False)
            self.ptrace_started=False
        return res

    def write_bytes(self, address, data):
        if not self.ptrace_started:
            self.ptrace_attach()

        c_pid = c_pid_t(self.pid)
        null = ctypes.c_void_p()


        #we can only copy data per range of 4 or 8 bytes
        word_size=ctypes.sizeof(ctypes.c_void_p)
        #mprotect(address, len(data)+(len(data)%word_size), PROT_WRITE|PROT_READ)
        for i in range(0, len(data), word_size):
            word=data[i:i+word_size]
            if len(word)<word_size: #we need to let some data untouched, so let's read at given offset to complete our 8 bytes
                existing_data=self.read_bytes(int(address)+i+len(word), bytes=(word_size-len(word)))
                word+=existing_data
            if sys.byteorder=="little":
                word=word[::-1]

            attempt=0
            err = c_ptrace(ctypes.c_int(PTRACE_POKEDATA), c_pid, int(address)+i, int(word.encode("hex"), 16))
            if err != 0:
                error=errno.errorcode.get(ctypes.get_errno(), 'UNKNOWN')
                raise OSError("Error using PTRACE_POKEDATA: %s"%error)

        self.ptrace_detach()
        return True

    def read_bytes(self, address, bytes = 4):
        if self.read_ptrace:
            self.ptrace_attach()
        data=b''
        if not LARGE_FILE_SUPPORT:
            mem_file.seek(address)
            data=mem_file.read(bytes)
        else:
            lseek64(self.mem_file, address, os.SEEK_SET)
            data=b""
            try:
                data=os.read(self.mem_file, bytes)
            except Exception as e:
                logger.info("Error reading %s at %s: %s"%((bytes),address, e))
        if self.read_ptrace:
            self.ptrace_detach()
        return data
