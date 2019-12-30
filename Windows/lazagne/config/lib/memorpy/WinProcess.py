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

from ctypes import pointer, sizeof, windll, create_string_buffer, c_ulong, byref, GetLastError, c_bool, WinError
from .structures import *
import copy
import struct
# import utils
import platform
from .BaseProcess import BaseProcess, ProcessException

psapi       = windll.psapi
kernel32    = windll.kernel32
advapi32    = windll.advapi32

IsWow64Process=None
if hasattr(kernel32,'IsWow64Process'):
    IsWow64Process=kernel32.IsWow64Process
    IsWow64Process.restype = c_bool
    IsWow64Process.argtypes = [c_void_p, POINTER(c_bool)]

class WinProcess(BaseProcess):

    def __init__(self, pid=None, name=None, debug=True):
        """ Create and Open a process object from its pid or from its name """
        super(WinProcess, self).__init__()
        if pid:
            self._open(int(pid), debug=debug)
            
        elif name:
            self._open_from_name(name, debug=debug)
        else:
            raise ValueError("You need to instanciate process with at least a name or a pid")
        
        if self.is_64bit():
            si = self.GetNativeSystemInfo()
            self.max_addr = si.lpMaximumApplicationAddress
        else:
            si = self.GetSystemInfo()
            self.max_addr = 2147418111
        self.min_addr = si.lpMinimumApplicationAddress


    def __del__(self):
        self.close()

    def is_64bit(self):
        if not "64" in platform.machine():
            return False
        iswow64 = c_bool(False)
        if IsWow64Process is None:
            return False
        if not IsWow64Process(self.h_process, byref(iswow64)):
            raise WinError()
        return not iswow64.value

    @staticmethod
    def list():
        processes=[]
        arr = c_ulong * 256
        lpidProcess= arr()
        cb = sizeof(lpidProcess)
        cbNeeded = c_ulong()
        hModule = c_ulong()
        count = c_ulong()
        modname = create_string_buffer(100)
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010

        psapi.EnumProcesses(byref(lpidProcess), cb, byref(cbNeeded))
        nReturned = int(cbNeeded.value/sizeof(c_ulong()))

        pidProcess = [i for i in lpidProcess][:nReturned]
        for pid in pidProcess:
            proc={ "pid": int(pid) }
            hProcess = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if hProcess:
                psapi.EnumProcessModules(hProcess, byref(hModule), sizeof(hModule), byref(count))
                psapi.GetModuleBaseNameA(hProcess, hModule.value, modname, sizeof(modname))
                proc["name"]=modname.value.decode()
                kernel32.CloseHandle(hProcess)
            processes.append(proc)
        return processes

    @staticmethod
    def processes_from_name(processName):
        processes = []
        for process in WinProcess.list():
            if processName == process.get("name", None) or (process.get("name","").lower().endswith(".exe") and process.get("name","")[:-4]==processName):
                processes.append(process)

        if len(processes) > 0:
            return processes

    @staticmethod
    def name_from_process(dwProcessId):
        process_list = WinProcess.list()
        for process in process_list:
            if process.pid == dwProcessId:
                return process.get("name", None)

        return False

    def _open(self, dwProcessId, debug=False):
        if debug:
            ppsidOwner              = DWORD()
            ppsidGroup              = DWORD()
            ppDacl                  = DWORD()
            ppSacl                  = DWORD()
            ppSecurityDescriptor    = SECURITY_DESCRIPTOR()

            process = kernel32.OpenProcess(262144, 0, dwProcessId)
            advapi32.GetSecurityInfo(kernel32.GetCurrentProcess(), 6, 0, byref(ppsidOwner), byref(ppsidGroup), byref(ppDacl), byref(ppSacl), byref(ppSecurityDescriptor))
            advapi32.SetSecurityInfo(process, 6, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, None, None, ppSecurityDescriptor.dacl, ppSecurityDescriptor.group)
            kernel32.CloseHandle(process)
        self.h_process = kernel32.OpenProcess(2035711, 0, dwProcessId)
        if self.h_process is not None:
            self.isProcessOpen = True
            self.pid = dwProcessId
            return True
        return False

    def close(self):
        if self.h_process is not None:
            ret = kernel32.CloseHandle(self.h_process) == 1
            if ret:
                self.h_process = None
                self.pid = None
                self.isProcessOpen = False
            return ret
        return False

    def _open_from_name(self, processName, debug=False):
        processes = self.processes_from_name(processName)
        if not processes:
            raise ProcessException("can't get pid from name %s" % processName)
        elif len(processes)>1:
            raise ValueError("There is multiple processes with name %s. Please select a process from its pid instead"%processName)
        if debug:
            self._open(processes[0]["pid"], debug=True)
        else:
            self._open(processes[0]["pid"], debug=False)

    def GetSystemInfo(self):
        si = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(si))
        return si

    def GetNativeSystemInfo(self):
        si = SYSTEM_INFO()
        kernel32.GetNativeSystemInfo(byref(si))
        return si

    def VirtualQueryEx(self, lpAddress):
        mbi = MEMORY_BASIC_INFORMATION()
        if not VirtualQueryEx(self.h_process, lpAddress, byref(mbi), sizeof(mbi)):
            raise ProcessException('Error VirtualQueryEx: 0x%08X' % lpAddress)
        return mbi

    def VirtualQueryEx64(self, lpAddress):
        mbi = MEMORY_BASIC_INFORMATION64()
        if not VirtualQueryEx64(self.h_process, lpAddress, byref(mbi), sizeof(mbi)):
            raise ProcessException('Error VirtualQueryEx: 0x%08X' % lpAddress)
        return mbi

    def VirtualProtectEx(self, base_address, size, protection):
        old_protect = c_ulong(0)
        if not kernel32.VirtualProtectEx(self.h_process, base_address, size, protection, byref(old_protect)):
            raise ProcessException('Error: VirtualProtectEx(%08X, %d, %08X)' % (base_address, size, protection))
        return old_protect.value

    def iter_region(self, start_offset=None, end_offset=None, protec=None, optimizations=None):
        
        offset = start_offset or self.min_addr
        end_offset = end_offset or self.max_addr

        while True:
            if offset >= end_offset:
                break
            mbi = self.VirtualQueryEx(offset)
            offset = mbi.BaseAddress
            chunk = mbi.RegionSize
            protect = mbi.Protect
            state = mbi.State
            #print "offset: %s, chunk:%s"%(offset, chunk)
            if state & MEM_FREE or state & MEM_RESERVE:
                offset += chunk
                continue
            if protec:
                if not protect & protec or protect & PAGE_NOCACHE or protect & PAGE_WRITECOMBINE or protect & PAGE_GUARD:
                    offset += chunk
                    continue
            yield offset, chunk
            offset += chunk

    def write_bytes(self, address, data):
        address = int(address)
        if not self.isProcessOpen:
            raise ProcessException("Can't write_bytes(%s, %s), process %s is not open" % (address, data, self.pid))
        buffer = create_string_buffer(data)
        sizeWriten = c_size_t(0)
        bufferSize = sizeof(buffer) - 1
        _address = address
        _length = bufferSize + 1
        try:
            old_protect = self.VirtualProtectEx(_address, _length, PAGE_EXECUTE_READWRITE)
        except:
            pass

        res = kernel32.WriteProcessMemory(self.h_process, address, buffer, bufferSize, byref(sizeWriten))
        try:
            self.VirtualProtectEx(_address, _length, old_protect)
        except:
            pass

        return res

    def read_bytes(self, address, bytes = 4, use_NtWow64ReadVirtualMemory64=False):
        #print "reading %s bytes from addr %s"%(bytes, address)
        if use_NtWow64ReadVirtualMemory64:
            if NtWow64ReadVirtualMemory64 is None:
                raise WindowsError("NtWow64ReadVirtualMemory64 is not available from a 64bit process")
            RpM = NtWow64ReadVirtualMemory64
        else:
            RpM = ReadProcessMemory

        address = int(address)
        buffer = create_string_buffer(bytes)
        bytesread = c_size_t(0)
        data = b''
        length = bytes
        while length:
            if RpM(self.h_process, address, buffer, bytes, byref(bytesread)) or (use_NtWow64ReadVirtualMemory64 and GetLastError() == 0):
                if bytesread.value:
                    data += buffer.raw[:bytesread.value]
                    length -= bytesread.value
                    address += bytesread.value
                if not len(data):
                    raise ProcessException('Error %s in ReadProcessMemory(%08x, %d, read=%d)' % (GetLastError(),
                     address,
                     length,
                     bytesread.value))
                return data
            else:
                if GetLastError()==299: #only part of ReadProcessMemory has been done, let's return it
                    data += buffer.raw[:bytesread.value]
                    return data
                raise WinError()
            # data += buffer.raw[:bytesread.value]
            # length -= bytesread.value
            # address += bytesread.value
        return data

   
    def list_modules(self):
        module_list = []
        if self.pid is not None:
            hModuleSnap = CreateToolhelp32Snapshot(TH32CS_CLASS.SNAPMODULE, self.pid)
            if hModuleSnap is not None:
                module_entry = MODULEENTRY32()
                module_entry.dwSize = sizeof(module_entry)
                success = Module32First(hModuleSnap, byref(module_entry))
                while success:
                    if module_entry.th32ProcessID == self.pid:
                        module_list.append(copy.copy(module_entry))
                    success = Module32Next(hModuleSnap, byref(module_entry))

                kernel32.CloseHandle(hModuleSnap)
        return module_list

    def get_symbolic_name(self, address):
        for m in self.list_modules():
            if int(m.modBaseAddr) <= int(address) < int(m.modBaseAddr + m.modBaseSize):
                return '%s+0x%08X' % (m.szModule, int(address) - m.modBaseAddr)

        return '0x%08X' % int(address)

    def hasModule(self, module):
        if module[-4:] != '.dll':
            module += '.dll'
        module_list = self.list_modules()
        for m in module_list:
            if module in m.szExePath.split('\\'):
                return True
        return False
    

    def get_instruction(self, address):
        """
        Pydasm disassemble utility function wrapper. Returns the pydasm decoded instruction in self.instruction.
        """
        import pydasm
        try:
            data = self.read_bytes(int(address), 32)
        except:
            return 'Unable to disassemble at %08x' % address

        return pydasm.get_instruction(data, pydasm.MODE_32)

