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

from ctypes import Structure, c_long, c_int, c_uint, c_char, c_void_p, c_ubyte, c_ushort, c_ulong, c_ulonglong, windll, POINTER, sizeof, c_bool, c_size_t, c_longlong
from ctypes.wintypes import *

if sizeof(c_void_p) == 8:
    ULONG_PTR = c_ulonglong
else:
    ULONG_PTR = c_ulong


class SECURITY_DESCRIPTOR(Structure): 
    _fields_ = [
        ('SID', DWORD),
        ('group', DWORD),
        ('dacl', DWORD),
        ('sacl', DWORD),
        ('test', DWORD)
    ]
PSECURITY_DESCRIPTOR = POINTER(SECURITY_DESCRIPTOR)

class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [('BaseAddress', c_void_p),
     ('AllocationBase', c_void_p),
     ('AllocationProtect', DWORD),
     ('RegionSize', c_size_t),
     ('State', DWORD),
     ('Protect', DWORD),
     ('Type', DWORD)]

# https://msdn.microsoft.com/fr-fr/library/windows/desktop/aa366775(v=vs.85).aspx
class MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [('BaseAddress', c_ulonglong),
     ('AllocationBase', c_ulonglong),
     ('AllocationProtect', DWORD),
     ('alignement1', DWORD),
     ('RegionSize', c_ulonglong),
     ('State', DWORD),
     ('Protect', DWORD),
     ('Type', DWORD),
     ('alignement2', DWORD)]



class SYSTEM_INFO(Structure):
    _fields_ = [('wProcessorArchitecture', WORD),
     ('wReserved', WORD),
     ('dwPageSize', DWORD),
     ('lpMinimumApplicationAddress', LPVOID),
     ('lpMaximumApplicationAddress', LPVOID),
     ('dwActiveProcessorMask', ULONG_PTR),
     ('dwNumberOfProcessors', DWORD),
     ('dwProcessorType', DWORD),
     ('dwAllocationGranularity', DWORD),
     ('wProcessorLevel', WORD),
     ('wProcessorRevision', WORD)]


class PROCESSENTRY32(Structure):
    _fields_ = [('dwSize', c_uint),
     ('cntUsage', c_uint),
     ('th32ProcessID', c_uint),
     ('th32DefaultHeapID', c_uint),
     ('th32ModuleID', c_uint),
     ('cntThreads', c_uint),
     ('th32ParentProcessID', c_uint),
     ('pcPriClassBase', c_long),
     ('dwFlags', DWORD),
     #('dwFlags', ULONG_PTR),
     ('szExeFile', c_char * 260),
     ('th32MemoryBase', c_long),
     ('th32AccessKey', c_long)]


class MODULEENTRY32(Structure):
    _fields_ = [('dwSize', c_uint),
     ('th32ModuleID', c_uint),
     ('th32ProcessID', c_uint),
     ('GlblcntUsage', c_uint),
     ('ProccntUsage', c_uint),
     ('modBaseAddr', c_uint),
     ('modBaseSize', c_uint),
     ('hModule', c_uint),
     ('szModule', c_char * 256),
     ('szExePath', c_char * 260)]


class THREADENTRY32(Structure):
    _fields_ = [('dwSize', c_uint),
     ('cntUsage', c_uint),
     ('th32ThreadID', c_uint),
     ('th32OwnerProcessID', c_uint),
     ('tpBasePri', c_uint),
     ('tpDeltaPri', c_uint),
     ('dwFlags', c_uint)]


class TH32CS_CLASS(object):
    INHERIT = 2147483648
    SNAPHEAPLIST = 1
    SNAPMODULE = 8
    SNAPMODULE32 = 16
    SNAPPROCESS = 2
    SNAPTHREAD = 4
    ALL = 2032639


Module32First = windll.kernel32.Module32First
Module32First.argtypes = [c_void_p, POINTER(MODULEENTRY32)]
Module32First.rettype = c_int
Module32Next = windll.kernel32.Module32Next
Module32Next.argtypes = [c_void_p, POINTER(MODULEENTRY32)]
Module32Next.rettype = c_int

Process32First = windll.kernel32.Process32First
Process32First.argtypes = [c_void_p, POINTER(PROCESSENTRY32)]
Process32First.rettype = c_int
Process32Next = windll.kernel32.Process32Next
Process32Next.argtypes = [c_void_p, POINTER(PROCESSENTRY32)]
Process32Next.rettype = c_int

CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.reltype = c_long
CreateToolhelp32Snapshot.argtypes = [c_int, c_int]

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [c_void_p]
CloseHandle.rettype = c_int

OpenProcess = windll.kernel32.OpenProcess
OpenProcess.argtypes = [c_void_p, c_int, c_long]
OpenProcess.rettype = c_long
OpenProcessToken = windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = (HANDLE, DWORD, POINTER(HANDLE))
OpenProcessToken.restype = BOOL

ReadProcessMemory = windll.kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t)]
ReadProcessMemory = windll.kernel32.ReadProcessMemory

WriteProcessMemory = windll.kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, c_size_t, POINTER(c_size_t)]
WriteProcessMemory.restype = BOOL

if sizeof(c_void_p) == 8:
    NtWow64ReadVirtualMemory64=None
else:
    try:
        NtWow64ReadVirtualMemory64 = windll.ntdll.NtWow64ReadVirtualMemory64
        NtWow64ReadVirtualMemory64.argtypes = [HANDLE, c_longlong, LPVOID, c_ulonglong, POINTER(c_ulong)] # NTSTATUS (__stdcall *NtWow64ReadVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesRead);
        NtWow64ReadVirtualMemory64.restype = BOOL
    except:
        NtWow64ReadVirtualMemory64=None

VirtualQueryEx = windll.kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [HANDLE, LPCVOID, POINTER(MEMORY_BASIC_INFORMATION), c_size_t]
VirtualQueryEx.restype = c_size_t

#VirtualQueryEx64 = windll.kernel32.VirtualQueryEx
#VirtualQueryEx64.argtypes = [HANDLE, LPCVOID, POINTER(MEMORY_BASIC_INFORMATION64), c_size_t]
#VirtualQueryEx64.restype = c_size_t

PAGE_EXECUTE_READWRITE = 64
PAGE_EXECUTE_READ = 32
PAGE_READONLY = 2
PAGE_READWRITE = 4
PAGE_NOCACHE = 512
PAGE_WRITECOMBINE = 1024
PAGE_GUARD = 256

MEM_COMMIT = 4096
MEM_FREE = 65536
MEM_RESERVE = 8192

UNPROTECTED_DACL_SECURITY_INFORMATION = 536870912
DACL_SECURITY_INFORMATION = 4