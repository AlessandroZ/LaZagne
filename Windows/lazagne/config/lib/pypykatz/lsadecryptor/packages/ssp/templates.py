#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
from ....commons.common import KatzSystemArchitecture, WindowsMinBuild, WindowsBuild
from ....commons.win_datatypes import POINTER, ULONG, LUID, KIWI_GENERIC_PRIMARY_CREDENTIAL
from ...package_commons import PackageTemplate


class SspTemplate(PackageTemplate):
	def __init__(self):
		super(SspTemplate, self).__init__('Ssp')
		self.signature = None
		self.first_entry_offset = None
		self.list_entry = None
	
	@staticmethod
	def get_template(sysinfo):
		template = SspTemplate()
		template.list_entry = PKIWI_SSP_CREDENTIAL_LIST_ENTRY
		template.log_template('list_entry', template.list_entry)
		
		if sysinfo.architecture == KatzSystemArchitecture.X64:
			if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\xc7\x43\x24\x43\x72\x64\x41\xff\x15'
				template.first_entry_offset = 16
				
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
				template.signature = b'\xc7\x47\x24\x43\x72\x64\x41\x48\x89\x47\x78\xff\x15'
				template.first_entry_offset = 20
				
			elif sysinfo.buildnumber >= WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x24\x43\x72\x64\x41\xff\x15'
				template.first_entry_offset = 14
			
			else:
				# currently this doesnt make sense, but keeping it here for future use
				raise Exception('Could not identify template! Architecture: %s sysinfo.buildnumber: %s' %
								(sysinfo.architecture, sysinfo.buildnumber))
		
		elif sysinfo.architecture == KatzSystemArchitecture.X86:
			template.signature = b'\x1c\x43\x72\x64\x41\xff\x15'
			template.first_entry_offset = 12
			
		else:
			raise Exception('Unknown architecture! %s' % sysinfo.architecture)

		return template


class PKIWI_SSP_CREDENTIAL_LIST_ENTRY(POINTER):
	def __init__(self, reader):
		super(PKIWI_SSP_CREDENTIAL_LIST_ENTRY, self).__init__(reader, KIWI_SSP_CREDENTIAL_LIST_ENTRY)


class KIWI_SSP_CREDENTIAL_LIST_ENTRY:
	def __init__(self, reader):
		self.Flink = PKIWI_SSP_CREDENTIAL_LIST_ENTRY(reader)
		self.Blink = PKIWI_SSP_CREDENTIAL_LIST_ENTRY(reader)
		self.References = ULONG(reader).value
		self.CredentialReferences = ULONG(reader).value
		self.LogonId = LUID(reader).value
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = ULONG(reader).value
		reader.align()
		self.credentials = KIWI_GENERIC_PRIMARY_CREDENTIAL(reader)
