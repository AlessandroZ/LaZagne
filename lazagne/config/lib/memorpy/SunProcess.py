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

from .BaseProcess import BaseProcess, ProcessException
import struct
import os

MA_READ      =    0x04
MA_WRITE     =    0x02
MA_EXEC      =    0x01
MA_SHARED    =    0x08
MA_ANON      =    0x40
MA_ISM       =    0x80
MA_NORESERVE =    0x100
MA_SHM       =    0x200
MA_RESERVED1 =    0x400
MA_OSM       =    0x800

PSINFO_T = struct.Struct(
    'iiiIIIIIIIILLLLHHLLLLLL16s80siiLLciILLcccchi8sLLIIIIII'
)

MAP_T = struct.Struct(
    'LL64sQiiii'
)

class SunProcess(BaseProcess):
    def __init__(self, pid=None, name=None, debug=True, ptrace=None):
        ''' Create and Open a process object from its pid or from its name '''
        super(SunProcess, self).__init__()
        self.pid = int(pid)
        self.pas = None
        self.writable = False
        if name and not self.pid:
            self.pid = SunProcess.pid_from_name(name)
        if not name and not self.pid:
            raise ValueError('You need to instanciate process with at least a name or a pid')
        try:
            self._open()
        except:
            pass

    def close(self):
        if self.pas:
            self.pas.close()

    def __del__(self):
        self.close()

    def _open(self):
        try:
            self.pas = open('/proc/%d/as'%(self.pid), 'w+')
            self.writable = True
        except IOError:
            self.pas = open('/proc/%d/as'%(self.pid))

        self.isProcessOpen = True

    @staticmethod
    def _name_args(pid):
        with open('/proc/%d/psinfo'%(int(pid))) as psinfo:
            items = PSINFO_T.unpack_from(psinfo.read())
            return items[23].rstrip('\x00'), items[24].rstrip('\x00')

    @staticmethod
    def list():
        processes=[]
        for pid in os.listdir('/proc'):
            try:
                pid = int(pid)
                name, _ = SunProcess._name_args(pid)
                processes.append({
                    'pid': pid,
                    'name': name
                })
            except:
                pass

        return processes

    @staticmethod
    def pid_from_name(name):
        processes=[]
        for pid in os.listdir('/proc'):
            try:
                pid = int(pid)
                pname, cmdline = SunProcess._name_args(pid)
                if name in pname:
                    return pid
                if name in cmdline.split(' ', 1)[0]:
                    return pid
            except:
                pass

        raise ProcessException('No process with such name: %s'%name)

    def iter_region(self, start_offset=None, end_offset=None, protec=None, optimizations=None):
        """
            optimizations :
                i for inode==0 (no file mapping)
                s to avoid scanning shared regions
                x to avoid scanning x regions
                r don't scan ronly regions
        """
        if not self.isProcessOpen:
            return

        with open('/proc/%d/map'%(self.pid)) as maps_file:
            while True:
                mapping = maps_file.read(MAP_T.size)

                if not mapping:
                    break

                start, size, name, offset, flags, pagesize, shmid, filler = MAP_T.unpack(mapping)

                if start_offset is not None:
                    if start < start_offset:
                        continue

                if end_offset is not None:
                    if start > end_offset:
                        continue

                if not flags & MA_READ:
                    continue

                if optimizations:
                    if 'i' in optimizations and not flags & MA_ANON:
                        continue
                    if 's' in optimizations and flags & MA_SHM:
                        continue
                    # in sunos it's quite common when this flag is set, so let's use other letter
                    if 'X' in optimizations and flags & MA_EXEC:
                        continue
                    if 'r' in optimizations and not flags & MA_WRITE:
                        continue

                yield start, size

    def write_bytes(self, address, data):
        if not self.pas or not self.writable:
            return False

        self.pas.seek(address)
        self.pas.write(data)

        return True

    def read_bytes(self, address, bytes = 4):
        if not self.pas:
            return

        self.pas.seek(address)
        return self.pas.read(bytes)
