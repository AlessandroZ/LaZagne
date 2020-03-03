#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#

from ...package_commons import PackageTemplate
from ....commons.common import KatzSystemArchitecture, WindowsMinBuild
from ....commons.win_datatypes import POINTER, ULONG, PWSTR, PVOID, LSA_UNICODE_STRING, LIST_ENTRY


class CredmanTemplate(PackageTemplate):
	def __init__(self):
		super(CredmanTemplate, self).__init__('Credman')
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None
		
	@staticmethod
	def get_template(sysinfo):
		template = CredmanTemplate()
		
		if sysinfo.architecture == KatzSystemArchitecture.X64:	
			if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY_5
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY_60
			else:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY
		else:
			if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY_5_X86
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY_60_X86
			else:
				template.list_entry = KIWI_CREDMAN_LIST_ENTRY_X86
			
		template.log_template('list_entry', template.list_entry)

		return template


class PKIWI_CREDMAN_LIST_ENTRY_5_X86(POINTER):
	def __init__(self, reader):
		super(PKIWI_CREDMAN_LIST_ENTRY_5_X86, self).__init__(reader, KIWI_CREDMAN_LIST_ENTRY_5_X86)


class KIWI_CREDMAN_LIST_ENTRY_5_X86:
	def __init__(self, reader):
		# IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		#
		reader.move(reader.tell() - 32)
		reader.align()  # not sure if it's needed here
		#
		self.cbEncPassword = ULONG(reader).value
		reader.align()
		self.encPassword = PWSTR
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.UserName = PWSTR(reader)
		self.cbUserName = ULONG(reader).value
		reader.align()
		self.Flink = PKIWI_CREDMAN_LIST_ENTRY_5
		self.Blink = PKIWI_CREDMAN_LIST_ENTRY_5
		self.server1 = LSA_UNICODE_STRING
		self.unk6 = PVOID(reader)
		self.unk7 = PVOID(reader)
		self.user = LSA_UNICODE_STRING(reader)
		self.unk8 = ULONG(reader).value
		reader.align()
		self.server2 = LSA_UNICODE_STRING


class PKIWI_CREDMAN_LIST_ENTRY_60_X86(POINTER):
	def __init__(self, reader):
		super(PKIWI_CREDMAN_LIST_ENTRY_60_X86, self).__init__(reader, KIWI_CREDMAN_LIST_ENTRY_60_X86)


class KIWI_CREDMAN_LIST_ENTRY_60_X86:
	def __init__(self, reader):
		# IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		reader.move(reader.tell() - 32)
		reader.align()  # not sure if it's needed here

		# input('KIWI_CREDMAN_LIST_ENTRY_60 \n%s' % hexdump(reader.peek(0x200), start = reader.tell()))
		self.cbEncPassword = ULONG(reader).value
		reader.align()
		self.encPassword = PWSTR(reader)
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.UserName = PWSTR(reader)
		self.cbUserName = ULONG(reader).value
		reader.align()
		self.Flink = PKIWI_CREDMAN_LIST_ENTRY_60
		self.Blink = PKIWI_CREDMAN_LIST_ENTRY_60
		self.type = LSA_UNICODE_STRING(reader)
		self.unk5 = PVOID(reader)
		self.server1 = LSA_UNICODE_STRING(reader)
		self.unk6 = PVOID(reader)
		self.unk7 = PVOID(reader)
		self.unk8 = PVOID(reader)
		self.unk9 = PVOID(reader)
		self.unk10 = PVOID(reader)
		self.user = LSA_UNICODE_STRING(reader)
		self.unk11 = ULONG(reader).value
		reader.align()
		self.server2 = LSA_UNICODE_STRING(reader)


class PKIWI_CREDMAN_LIST_ENTRY_X86(POINTER):
	def __init__(self, reader):
		super(PKIWI_CREDMAN_LIST_ENTRY_X86, self).__init__(reader, KIWI_CREDMAN_LIST_ENTRY_X86)


class KIWI_CREDMAN_LIST_ENTRY_X86:
	def __init__(self, reader):
		# IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		reader.move(reader.tell() - 32)
		reader.align()  # not sure if it's needed here

		self.cbEncPassword = ULONG(reader).value
		reader.align()
		self.encPassword = PWSTR(reader)
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.UserName = PWSTR(reader)
		self.cbUserName = ULONG(reader).value
		reader.align()
		self.Flink = PKIWI_CREDMAN_LIST_ENTRY(reader)
		self.Blink = PKIWI_CREDMAN_LIST_ENTRY(reader)
		self.unk4 = LIST_ENTRY(reader)
		self.type = LSA_UNICODE_STRING(reader)
		self.unk5 = PVOID(reader)
		self.server1 = LSA_UNICODE_STRING(reader)
		self.unk6 = PVOID(reader)
		self.unk7 = PVOID(reader)
		self.unk8 = PVOID(reader)
		self.unk9 = PVOID(reader)
		self.unk10 = PVOID(reader)
		self.user = LSA_UNICODE_STRING(reader)
		self.unk11 = ULONG(reader).value
		reader.align()
		self.server2 = LSA_UNICODE_STRING(reader)


class PKIWI_CREDMAN_LIST_ENTRY_5(POINTER):
	def __init__(self, reader):
		super(PKIWI_CREDMAN_LIST_ENTRY_5, self).__init__(reader, KIWI_CREDMAN_LIST_ENTRY_5)


class KIWI_CREDMAN_LIST_ENTRY_5:
	def __init__(self, reader):
		# IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS

		reader.move(reader.tell() - 56)
		reader.align()  # not sure if it's needed here

		self.cbEncPassword = ULONG(reader).value
		reader.align()
		self.encPassword = PWSTR
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.UserName = PWSTR(reader)
		self.cbUserName = ULONG(reader).value
		reader.align()
		self.Flink = PKIWI_CREDMAN_LIST_ENTRY_5
		self.Blink = PKIWI_CREDMAN_LIST_ENTRY_5
		self.server1 = LSA_UNICODE_STRING
		self.unk6 = PVOID(reader)
		self.unk7 = PVOID(reader)
		self.user = LSA_UNICODE_STRING(reader)
		self.unk8 = ULONG(reader).value
		reader.align()
		self.server2 = LSA_UNICODE_STRING


class PKIWI_CREDMAN_LIST_ENTRY_60(POINTER):
	def __init__(self, reader):
		super(PKIWI_CREDMAN_LIST_ENTRY_60, self).__init__(reader, KIWI_CREDMAN_LIST_ENTRY_60)


class KIWI_CREDMAN_LIST_ENTRY_60:
	def __init__(self, reader):
		# IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		reader.move(reader.tell() - 56)
		reader.align()  # not sure if it's needed here

		# input('KIWI_CREDMAN_LIST_ENTRY_60 \n%s' % hexdump(reader.peek(0x200), start = reader.tell()))
		self.cbEncPassword = ULONG(reader).value
		reader.align()
		self.encPassword = PWSTR(reader)
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.UserName = PWSTR(reader)
		self.cbUserName = ULONG(reader).value
		reader.align()
		self.Flink = PKIWI_CREDMAN_LIST_ENTRY_60
		self.Blink = PKIWI_CREDMAN_LIST_ENTRY_60
		self.type = LSA_UNICODE_STRING(reader)
		self.unk5 = PVOID(reader)
		self.server1 = LSA_UNICODE_STRING(reader)
		self.unk6 = PVOID(reader)
		self.unk7 = PVOID(reader)
		self.unk8 = PVOID(reader)
		self.unk9 = PVOID(reader)
		self.unk10 = PVOID(reader)
		self.user = LSA_UNICODE_STRING(reader)
		self.unk11 = ULONG(reader).value
		reader.align()
		self.server2 = LSA_UNICODE_STRING(reader)


class PKIWI_CREDMAN_LIST_ENTRY(POINTER):
	def __init__(self, reader):
		super(PKIWI_CREDMAN_LIST_ENTRY, self).__init__(reader, KIWI_CREDMAN_LIST_ENTRY)


class KIWI_CREDMAN_LIST_ENTRY:
	def __init__(self, reader):
		# IMPORTANT NOTICE, THE STRUCTURE STARTS BEFORE THE FLINK/BLINK POINTER, SO WE NEED TO READ BACKWARDS
		# input('KIWI_CREDMAN_LIST_ENTRY \n%s' % hexdump(reader.peek(0x50), start = reader.tell()))
		reader.move(reader.tell() - 56)
		reader.align()  # not sure if it's needed here

		# input('KIWI_CREDMAN_LIST_ENTRY \n%s' % hexdump(reader.peek(0x200), start = reader.tell()))
		self.cbEncPassword = ULONG(reader).value
		reader.align()
		self.encPassword = PWSTR(reader)
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = PVOID(reader)
		self.unk3 = PVOID(reader)
		self.UserName = PWSTR(reader)
		self.cbUserName = ULONG(reader).value
		reader.align()
		self.Flink = PKIWI_CREDMAN_LIST_ENTRY(reader)
		self.Blink = PKIWI_CREDMAN_LIST_ENTRY(reader)
		self.unk4 = LIST_ENTRY(reader)
		self.type = LSA_UNICODE_STRING(reader)
		self.unk5 = PVOID(reader)
		self.server1 = LSA_UNICODE_STRING(reader)
		self.unk6 = PVOID(reader)
		self.unk7 = PVOID(reader)
		self.unk8 = PVOID(reader)
		self.unk9 = PVOID(reader)
		self.unk10 = PVOID(reader)
		self.user = LSA_UNICODE_STRING(reader)
		self.unk11 = ULONG(reader).value
		reader.align()
		self.server2 = LSA_UNICODE_STRING(reader)


class PKIWI_CREDMAN_LIST_STARTER(POINTER):
	def __init__(self, reader):
		super(PKIWI_CREDMAN_LIST_STARTER, self).__init__(reader, KIWI_CREDMAN_LIST_STARTER)
		

class KIWI_CREDMAN_LIST_STARTER:
	def __init__(self, reader):
		self.unk0 = ULONG(reader)
		reader.align()
		self.start = PKIWI_CREDMAN_LIST_ENTRY(reader)
		# ...


class PKIWI_CREDMAN_SET_LIST_ENTRY(POINTER):
	def __init__(self, reader):
		super(PKIWI_CREDMAN_SET_LIST_ENTRY, self).__init__(reader, KIWI_CREDMAN_SET_LIST_ENTRY)


class KIWI_CREDMAN_SET_LIST_ENTRY:
	def __init__(self, reader):
		self.Flink = PKIWI_CREDMAN_SET_LIST_ENTRY(reader)
		self.Blink = PKIWI_CREDMAN_SET_LIST_ENTRY(reader)
		self.unk0 = ULONG(reader).value
		reader.align()
		self.list1 = PKIWI_CREDMAN_LIST_STARTER(reader)
		self.list2 = PKIWI_CREDMAN_LIST_STARTER(reader)
