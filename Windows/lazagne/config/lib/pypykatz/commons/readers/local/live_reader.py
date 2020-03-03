#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
from .common.live_reader_ctypes import ReadProcessMemory, get_lsass_pid, OpenProcess, PROCESS_ALL_ACCESS, \
	EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, VirtualQueryEx
from .common.privileges import enable_debug_privilege
from .common.version import PROCESSOR_ARCHITECTURE, GetSystemInfo

import logging
import sys
import struct
import copy
import platform
import os
import ntpath

from ctypes import WinError, get_last_error

try:
	import winreg
except ImportError:
	import _winreg as winreg


class Module:
	def __init__(self):
		self.name = None
		self.baseaddress = None
		self.size = None
		self.endaddress = None
		self.pages = []
		self.versioninfo = None
		self.checksum = None
		self.timestamp = None

	def inrange(self, addr):
		return self.baseaddress <= addr < self.endaddress
	
	@staticmethod
	def parse(name, module_info, timestamp):
		m = Module()
		m.name = name
		m.baseaddress = module_info.lpBaseOfDll
		m.size = module_info.SizeOfImage
		m.endaddress = m.baseaddress + m.size
		m.timestamp = timestamp
		return m
		
	def __str__(self):
		return '%s %s %s %s %s' % (self.name, hex(self.baseaddress), hex(self.size), hex(self.endaddress), self.timestamp)


class Page:
	def __init__(self):
		self.BaseAddress = None
		self.AllocationBase = None
		self.AllocationProtect = None
		self.RegionSize = None
		self.EndAddress = None
		self.data = None

	@staticmethod
	def parse(page_info):
		p = Page()
		p.BaseAddress = page_info.BaseAddress
		p.AllocationBase = page_info.AllocationBase
		p.AllocationProtect = page_info.AllocationProtect
		p.RegionSize = min(page_info.RegionSize, 100*1024*1024)  # TODO: need this currently to stop infinite search
		p.EndAddress = page_info.BaseAddress + page_info.RegionSize
		return p
		
	def read_data(self, lsass_process_handle):
		self.data = ReadProcessMemory(lsass_process_handle, self.BaseAddress, self.RegionSize)
		
	def inrange(self, addr):
		return self.BaseAddress <= addr < self.EndAddress

	def search(self, pattern, lsass_process_handle):
		if len(pattern) > self.RegionSize:
			return []
		data = ReadProcessMemory(lsass_process_handle, self.BaseAddress, self.RegionSize)
		fl = []
		offset = 0
		while len(data) > len(pattern):
			marker = data.find(pattern)
			if marker == -1:
				return fl
			fl.append(marker + offset + self.BaseAddress)
			data = data[marker+1:]
			offset = marker + 1

		return fl

	def __str__(self):
		return '0x%08x 0x%08x %s 0x%08x' % (self.BaseAddress, self.AllocationBase, self.AllocationProtect, self.RegionSize)

		
class BufferedLiveReader:
	def __init__(self, reader):
		self.reader = reader
		self.pages = []
		self.current_segment = None
		self.current_position = None

	def _select_segment(self, requested_position):
		# check if we have semgnet for requested address in cache
		for page in self.pages:
			if page.inrange(requested_position):
				self.current_segment = page
				self.current_position = requested_position
				return

		# not in cache, check if it's present in memory space. if yes then create a new buffered memeory object, and copy data
		for page in self.reader.pages:
			if page.inrange(requested_position):
				page.read_data(self.reader.lsass_process_handle)
				newsegment = copy.deepcopy(page)
				self.pages.append(newsegment)
				self.current_segment = newsegment
				self.current_position = requested_position
				return

		raise Exception('Memory address 0x%08x is not in process memory space' % requested_position)
		
	def seek(self, offset, whence=0):
		"""
		Changes the current address to an offset of offset. The whence parameter controls from which position should we count the offsets.
		0: beginning of the current memory segment
		1: from current position
		2: from the end of the current memory segment
		If you wish to move out from the segment, use the 'move' function
		"""
		if whence == 0:
			t = self.current_segment.BaseAddress + offset
		elif whence == 1:
			t = self.current_position + offset
		elif whence == 2:
			t = self.current_segment.EndAddress - offset
		else:
			raise Exception('Seek function whence value must be between 0-2')

		if not self.current_segment.inrange(t):
			raise Exception('Seek would cross memory segment boundaries (use move)')

		self.current_position = t
		return
		
	def move(self, address):
		"""
		Moves the buffer to a virtual address specified by address
		"""
		self._select_segment(address)
		return

	def align(self, alignment=None):
		"""
		Repositions the current reader to match architecture alignment
		"""
		if alignment is None:
			if self.reader.processor_architecture == PROCESSOR_ARCHITECTURE.AMD64:
				alignment = 8
			else:
				alignment = 4
		offset = self.current_position % alignment
		if offset == 0:
			return
		offset_to_aligned = (alignment - offset) % alignment
		self.seek(offset_to_aligned, 1)
		return

	def tell(self):
		"""
		Returns the current virtual address
		"""
		return self.current_position

	def peek(self, length):
		"""
		Returns up to length bytes from the current memory segment
		"""
		t = self.current_position + length
		if not self.current_segment.inrange(t):
			raise Exception('Would read over segment boundaries!')
		return self.current_segment.data[self.current_position - self.current_segment.BaseAddress:t - self.current_segment.BaseAddress]
	
	def read(self, size = -1):
		"""
		Returns data bytes of size size from the current segment. If size is -1 it returns all the remaining data bytes from memory segment
		"""
		if size < -1:
			raise Exception('You should not be doing this')
		if size == -1:
			t = self.current_segment.remaining_len(self.current_position)
			if not t:
				return None
			
			old_new_pos = self.current_position
			self.current_position = self.current_segment.EndAddress
			return self.current_segment.data[old_new_pos - self.current_segment.BaseAddress:]
		
		t = self.current_position + size
		if not self.current_segment.inrange(t):
			raise Exception('Would read over segment boundaries!')
		
		old_new_pos = self.current_position
		self.current_position = t		
		return self.current_segment.data[old_new_pos - self.current_segment.BaseAddress :t - self.current_segment.BaseAddress]
	
	def read_int(self):
		"""
		Reads an integer. The size depends on the architecture. 
		Reads a 4 byte small-endian singed int on 32 bit arch
		Reads an 8 byte small-endian singed int on 64 bit arch
		"""
		if self.reader.processor_architecture == PROCESSOR_ARCHITECTURE.AMD64:
			return struct.unpack("<q", self.read(8))[0]
		else:
			return struct.unpack("<l", self.read(4))[0]

	def read_uint(self):
		"""
		Reads an integer. The size depends on the architecture. 
		Reads a 4 byte small-endian unsinged int on 32 bit arch
		Reads an 8 byte small-endian unsinged int on 64 bit arch
		"""
		if self.reader.processor_architecture == PROCESSOR_ARCHITECTURE.AMD64:
			return struct.unpack("<Q", self.read(8))[0]
		else:
			return struct.unpack("<L", self.read(4))[0]
	
	def find(self, pattern):
		"""
		Searches for a pattern in the current memory segment
		"""
		pos = self.current_segment.data.find(pattern)
		if pos == -1:
			return -1
		return pos + self.current_position
		
	def find_all(self, pattern):
		"""
		Searches for all occurrences of a pattern in the current memory segment, returns all occurrences as a list
		"""
		pos = []
		last_found = -1
		while True:
			last_found = self.current_segment.data.find(pattern, last_found + 1)
			if last_found == -1:
				break
			pos.append(last_found + self.current_segment.start_address)
			
		return pos
		
	def find_global(self, pattern):
		"""
		Searches for the pattern in the whole process memory space and returns the first occurrence.
		This is exhaustive!
		"""
		pos_s = self.reader.search(pattern)
		if len(pos_s) == 0:
			return -1
		
		return pos_s[0]
		
	def find_all_global(self, pattern):
		"""
		Searches for the pattern in the whole process memory space and returns a list of addresses where the pattern begins.
		This is exhaustive!
		"""
		return self.reader.search(pattern)
		
	def get_ptr(self, pos):
		self.move(pos)
		return self.read_uint()
		# raw_data = self.read(pos, self.sizeof_ptr)
		# return struct.unpack(self.unpack_ptr, raw_data)[0]
	
	def get_ptr_with_offset(self, pos):
		if self.reader.processor_architecture == PROCESSOR_ARCHITECTURE.AMD64:
			self.move(pos)
			ptr = struct.unpack("<l", self.read(4))[0]
			return pos + 4 + ptr
		else:
			self.move(pos)
			return self.read_uint()
	
	def find_in_module(self, module_name, pattern):
		t = self.reader.search_module(module_name, pattern)
		return t		

		
class LiveReader:
	def __init__(self):
		self.processor_architecture = None
		self.lsass_process_name = 'lsass.exe'
		self.lsass_process_handle = None
		self.current_position = None
		self.BuildNumber = None
		self.modules = []
		self.pages = []
		self.msv_dll_timestamp = None  # a special place in our hearts....
		self.sanity_check()
		self.setup()

	def sanity_check(self):
		"""
		Check if user is insane
		Windows API functions don't like when a 32 bit process is accessing a 64 bit process's memory space,
		Therefore you must use a 64 bit python on a 64bit Windows and a 32bit python on a 32bit Windows
		"""
		is_python_64 = sys.maxsize > 2**32
		is_windows = platform.system() == 'Windows'
		is_windows_64 = platform.machine().endswith('64')
		if is_windows == False:
			raise Exception('This will only run on Windows')

		if is_windows_64 != is_python_64:
			raise Exception('Python interpreter must be the same architecure of the OS you are running it on.')

	def setup(self):
		logging.log(1, 'Enabling debug privilege')
		enable_debug_privilege()
		logging.log(1, 'Getting generic system info')
		sysinfo = GetSystemInfo()
		self.processor_architecture = PROCESSOR_ARCHITECTURE(sysinfo.id.w.wProcessorArchitecture)
		
		logging.log(1, 'Getting build number')
		# self.BuildNumber = GetVersionEx().dwBuildNumber #this one doesnt work reliably on frozen binaries :(((
		key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\')
		buildnumber, t = winreg.QueryValueEx(key, 'CurrentBuildNumber')
		self.BuildNumber = int(buildnumber)

		logging.log(1, 'Searching for lsass.exe')
		pid = get_lsass_pid()
		logging.log(1, 'Lsass.exe found at PID %d' % pid)
		logging.log(1, 'Opening lsass.exe')
		self.lsass_process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
		if self.lsass_process_handle is None:
			raise Exception('Failed to open lsass.exe Reason: %s' % WinError(get_last_error()))

		logging.log(1, 'Enumerating modules')
		module_handles = EnumProcessModules(self.lsass_process_handle)
		for module_handle in module_handles:
			
			module_file_path = GetModuleFileNameExW(self.lsass_process_handle, module_handle)
			logging.log(1, module_file_path)
			timestamp = 0
			if ntpath.basename(module_file_path).lower() == 'msv1_0.dll':
				timestamp = int(os.stat(module_file_path).st_ctime)
				self.msv_dll_timestamp = timestamp
			modinfo = GetModuleInformation(self.lsass_process_handle, module_handle)
			self.modules.append(Module.parse(module_file_path, modinfo, timestamp))
			
		logging.log(1, 'Found %d modules' % len(self.modules))
			
		current_address = sysinfo.lpMinimumApplicationAddress
		while current_address < sysinfo.lpMaximumApplicationAddress:
			page_info = VirtualQueryEx(self.lsass_process_handle, current_address)
			self.pages.append(Page.parse(page_info))
			
			current_address += page_info.RegionSize
			
		logging.log(1, 'Found %d pages' % len(self.pages))

		for page in self.pages:
			# self.log(str(page))
			for mod in self.modules:
				if mod.inrange(page.BaseAddress) == True:
					mod.pages.append(page)

		# for mod in self.modules:
		#	self.log('%s %d' % (mod.name, len(mod.pages)))

	def get_buffered_reader(self):
		return BufferedLiveReader(self)			
		
	def get_module_by_name(self, module_name):
		for mod in self.modules:
			if mod.name.lower().find(module_name.lower()) != -1:
				return mod
		return None	
	
	def search_module(self, module_name, pattern):
		mod = self.get_module_by_name(module_name)
		if mod is None:
			raise Exception('Could not find module! %s' % module_name)
		t = []
		for page in mod.pages:
			t += page.search(pattern, self.lsass_process_handle)
		# for ms in self.pages:
		#	if mod.baseaddress <= ms.start_virtual_address < mod.endaddress:
		#		t+= ms.search(pattern, self.lsass_process_handle)

		return t


if __name__ == '__main__':
	logging.basicConfig(level=1)
	lr = LiveReader()
	blr = lr.get_buffered_reader()
	
	blr.move(0x1000)
