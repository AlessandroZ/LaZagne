#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
import struct

from ...package_commons import PackageTemplate
from ....commons.common import WindowsBuild, WindowsMinBuild, KatzSystemArchitecture
from ....commons.win_datatypes import USHORT, ULONG, BOOLEAN, BYTE, LSA_UNICODE_STRING, ANSI_STRING, POINTER, PVOID, \
	DWORD, WORD, PSID, LUID, HANDLE


class MsvTemplate(PackageTemplate):
	def __init__(self):
		super(MsvTemplate, self).__init__('Msv')
		self.signature = None
		self.first_entry_offset = None
		self.offset2 = None
		self.list_entry = None
		self.encrypted_credentials_list_struct = None
		self.encrypted_credential_struct = None
		self.decrypted_credential_struct = None
	
	@staticmethod
	def get_template(sysinfo):
		template = MsvTemplate()
		template.encrypted_credentials_list_struct = KIWI_MSV1_0_CREDENTIAL_LIST
		template.log_template('encrypted_credentials_list_struct', template.encrypted_credentials_list_struct)
		template.encrypted_credential_struct = KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC
		template.log_template('encrypted_credential_struct', template.encrypted_credential_struct)
		# identify credential session list structure to be used
		if sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
			template.list_entry = PKIWI_MSV1_0_LIST_51
			
		elif sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
			template.list_entry = PKIWI_MSV1_0_LIST_52
		
		elif sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
			template.list_entry = PKIWI_MSV1_0_LIST_60
		
		elif sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
			# do not do that :)
			if sysinfo.msv_dll_timestamp > 0x53480000:
				template.list_entry = PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ
			else:
				template.list_entry = PKIWI_MSV1_0_LIST_61	
		
		elif sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
			template.list_entry = PKIWI_MSV1_0_LIST_62
		
		else:
			template.list_entry = PKIWI_MSV1_0_LIST_63
		
		template.log_template('list_entry', template.list_entry)
		if sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
			template.decrypted_credential_struct = MSV1_0_PRIMARY_CREDENTIAL_DEC
		elif sysinfo.buildnumber < WindowsBuild.WIN_10_1511.value:
			template.decrypted_credential_struct = MSV1_0_PRIMARY_CREDENTIAL_10_OLD_DEC
		elif sysinfo.buildnumber < WindowsBuild.WIN_10_1607.value:
			template.decrypted_credential_struct = MSV1_0_PRIMARY_CREDENTIAL_10_DEC
		else:
			template.decrypted_credential_struct = MSV1_0_PRIMARY_CREDENTIAL_10_1607_DEC
		
		template.log_template('decrypted_credential_struct', template.decrypted_credential_struct)
			
		if sysinfo.architecture == KatzSystemArchitecture.X64:
			if WindowsMinBuild.WIN_XP.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
				template.signature = b'\x4c\x8b\xdf\x49\xc1\xe3\x04\x48\x8b\xcb\x4c\x03\xd8'
				template.first_entry_offset = 0
				template.offset2 = -4
				
			elif WindowsMinBuild.WIN_2K3.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x4c\x8b\xdf\x49\xc1\xe3\x04\x48\x8b\xcb\x4c\x03\xd8'
				template.first_entry_offset = -45
				template.offset2 = -4
				
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				template.signature = b'\x33\xff\x45\x85\xc0\x41\x89\x75\x00\x4c\x8b\xe3\x0f\x84'
				template.first_entry_offset = 21#-4
				template.offset2 = 21
				
			elif WindowsMinBuild.WIN_7.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				template.signature = b'\x33\xf6\x45\x89\x2f\x4c\x8b\xf3\x85\xff\x0f\x84'
				template.first_entry_offset = 19
				template.offset2 = -4	
				
			elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74'
				template.first_entry_offset = 16
				template.offset2 = -4	
				
			elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x8b\xde\x48\x8d\x0c\x5b\x48\xc1\xe1\x05\x48\x8d\x05'
				template.first_entry_offset = 36
				template.offset2 = -6	
				
			elif WindowsBuild.WIN_10_1507.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1703.value:
				template.signature = b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74'
				template.first_entry_offset = 16
				template.offset2 = -4
				# template.signature = b'\x8b\xde\x48\x8d\x0c\x5b\x48\xc1\xe1\x05\x48\x8d\x05'
				# template.first_entry_offset = 36
				# template.offset2 = -6

			elif WindowsBuild.WIN_10_1703.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1803.value:
				template.signature = b'\x33\xff\x45\x89\x37\x48\x8b\xf3\x45\x85\xc9\x74'
				template.first_entry_offset = 23
				template.offset2 = -4
			
			elif WindowsBuild.WIN_10_1803.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1903.value:
				template.signature = b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc9\x74'
				template.first_entry_offset = 23
				template.offset2 = -4
				
			else:
				# 1903
				template.signature = b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74'
				template.first_entry_offset = 23
				template.offset2 = -4
		
		elif sysinfo.architecture == KatzSystemArchitecture.X86:
			if WindowsMinBuild.WIN_XP.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
				template.signature = b'\xff\x50\x10\x85\xc0\x0f\x84'
				template.first_entry_offset = 0
				template.offset2 = 24

			elif WindowsMinBuild.WIN_2K3.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
				template.signature = b'\x89\x71\x04\x89\x30\x8d\x04\xbd'
				template.first_entry_offset = -43
				template.offset2 = -11

			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				template.signature = b'\x89\x71\x04\x89\x30\x8d\x04\xbd'
				template.first_entry_offset = -11
				template.offset2 = -11
				
			elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				template.signature = b'\x8b\x45\xf8\x8b\x55\x08\x8b\xde\x89\x02\x89\x5d\xf0\x85\xc9\x74'
				template.first_entry_offset = 18
				template.offset2 = -4
				
			elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x8b\x4d\xe4\x8b\x45\xf4\x89\x75\xe8\x89\x01\x85\xff\x74'	
				template.first_entry_offset = 16
				template.offset2 = -4
			
			elif sysinfo.buildnumber >= WindowsBuild.WIN_10_1507.value:
				template.signature = b'\x8b\x4d\xe8\x8b\x45\xf4\x89\x75\xec\x89\x01\x85\xff\x74'
				template.first_entry_offset = 16
				template.offset2 = -4
			else:
				raise Exception('Could not identify template! sysinfo.buildnumber: %d' % sysinfo.buildnumber)
		
		else:
			raise Exception('Unknown Architecture: %s , Build number %s' % (sysinfo.architecture, sysinfo.buildnumber))

		return template
	
	
class MSV1_0_PRIMARY_CREDENTIAL_STRANGE_DEC:
	# this structure doesnt have username nor domainname, but has credentials :S
	# starts with
	size = 0x60

	def __init__(self, reader):
		self.unk1 = USHORT(reader).value
		self.unk2 = USHORT(reader).value
		self.unk_tag = reader.read(4)  # 0xcccccc
		self.unk_remaining_size = ULONG(reader).value  # 0x50
		reader.read(40)
		self.LengthOfNtOwfPassword = ULONG(reader).value
		self.NtOwfPassword = reader.read(16)
		self.LengthOfShaOwfPassword = ULONG(reader).value
		self.ShaOwPassword = reader.read(20)
		
		self.LogonDomainName = None
		self.UserName = None
		self.LmOwfPassword = None
		self.isNtOwfPassword = None
		self.isLmOwfPassword = None
		self.isShaOwPassword = None


class MSV1_0_PRIMARY_CREDENTIAL_DEC:
	def __init__(self, reader):
		self.LogonDomainName = LSA_UNICODE_STRING(reader)
		self.UserName = LSA_UNICODE_STRING(reader)
		self.NtOwfPassword = reader.read(16)
		self.LmOwfPassword = reader.read(16)
		self.ShaOwPassword = reader.read(20)
		self.isNtOwfPassword = BOOLEAN(reader).value
		self.isLmOwfPassword = BOOLEAN(reader).value
		self.isShaOwPassword = BOOLEAN(reader).value


class MSV1_0_PRIMARY_CREDENTIAL_10_OLD_DEC:
	def __init__(self, reader):
		self.LogonDomainName = LSA_UNICODE_STRING(reader)
		self.UserName = LSA_UNICODE_STRING(reader)
		self.isIso = BOOLEAN(reader).value
		self.isNtOwfPassword = BOOLEAN(reader).value
		self.isLmOwfPassword = BOOLEAN(reader).value
		self.isShaOwPassword = BOOLEAN(reader).value
		self.align0 = BYTE(reader).value
		self.align1 = BYTE(reader).value
		self.NtOwfPassword = reader.read(16)
		self.LmOwfPassword = reader.read(16)
		self.ShaOwPassword = reader.read(20)


class MSV1_0_PRIMARY_CREDENTIAL_10_DEC:
	def __init__(self, reader):
		self.LogonDomainName = LSA_UNICODE_STRING(reader)
		self.UserName = LSA_UNICODE_STRING(reader)
		self.isIso = BOOLEAN(reader).value
		self.isNtOwfPassword = BOOLEAN(reader).value
		self.isLmOwfPassword = BOOLEAN(reader).value
		self.isShaOwPassword = BOOLEAN(reader).value
		self.align0 = BYTE(reader).value
		self.align1 = BYTE(reader).value
		self.align2 = BYTE(reader).value
		self.align3 = BYTE(reader).value
		self.NtOwfPassword = reader.read(16)
		self.LmOwfPassword = reader.read(16)
		self.ShaOwPassword = reader.read(20)


class MSV1_0_PRIMARY_CREDENTIAL_10_1607_DEC:
	def __init__(self, reader):
		self.LogonDomainName = LSA_UNICODE_STRING(reader)
		self.UserName = LSA_UNICODE_STRING(reader)
		self.pNtlmCredIsoInProc = PVOID(reader).value
		self.isIso = BOOLEAN(reader).value
		self.isNtOwfPassword = BOOLEAN(reader).value
		self.isLmOwfPassword = BOOLEAN(reader).value
		self.isShaOwPassword = BOOLEAN(reader).value
		self.isDPAPIProtected = BOOLEAN(reader).value
		self.align0 = BYTE(reader).value
		self.align1 = BYTE(reader).value
		self.align2 = BYTE(reader).value
		self.unkD = DWORD(reader).value  # 1/2
		# stuff to be done! #pragma pack(push, 2)
		self.isoSize = WORD(reader).value  # 0000
		self.DPAPIProtected = reader.read(16)
		self.align3 = DWORD(reader).value  # 00000000
		# stuff to be done! #pragma pack(pop) 
		self.NtOwfPassword = reader.read(16)
		self.LmOwfPassword = reader.read(16)
		self.ShaOwPassword = reader.read(20)


class KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC:
	def __init__(self, reader):
		self.Flink = PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC(reader)
		self.Primary = ANSI_STRING(reader)
		reader.align()
		self.encrypted_credentials = LSA_UNICODE_STRING(reader)


class PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC(POINTER):
	def __init__(self, reader):
		super(PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC, self).__init__(reader, KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC)


class PKIWI_MSV1_0_CREDENTIAL_LIST(POINTER):
	def __init__(self, reader):
		super(PKIWI_MSV1_0_CREDENTIAL_LIST, self).__init__(reader, PKIWI_MSV1_0_CREDENTIAL_LIST)


class KIWI_MSV1_0_CREDENTIAL_LIST:
	def __init__(self, reader):
		self.Flink = PKIWI_MSV1_0_CREDENTIAL_LIST(reader)
		self.AuthenticationPackageId = DWORD(reader).value
		reader.align()
		self.PrimaryCredentials_ptr = PKIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC(reader)


class PKIWI_MSV1_0_CREDENTIAL_LIST(POINTER):
	def __init__(self, reader):
		super(PKIWI_MSV1_0_CREDENTIAL_LIST, self).__init__(reader, KIWI_MSV1_0_CREDENTIAL_LIST)


class PKIWI_MSV1_0_LIST_51(POINTER):
	def __init__(self, reader):
		super(PKIWI_MSV1_0_LIST_51, self).__init__(reader, KIWI_MSV1_0_LIST_51)


class KIWI_MSV1_0_LIST_51:
	def __init__(self, reader):
		self.Flink = PKIWI_MSV1_0_LIST_51(reader)
		self.Blink = PKIWI_MSV1_0_LIST_51(reader)
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.UserName = LSA_UNICODE_STRING(reader)
		self.Domaine = LSA_UNICODE_STRING(reader)
		self.unk0 = PVOID(reader).value
		self.unk1 = PVOID(reader).value
		self.pSid = PSID(reader)
		self.LogonType = ULONG(reader).value
		self.Session = ULONG(reader).value
		reader.align()
		self.LogonTime = struct.unpack("<Q", reader.read(8))[0]  # autoalign x86
		self.LogonServer = LSA_UNICODE_STRING(reader)
		self.Credentials_list_ptr = PKIWI_MSV1_0_CREDENTIAL_LIST(reader)
		self.unk19 = ULONG(reader).value
		reader.align()
		self.unk20 = PVOID(reader).value
		self.unk21 = PVOID(reader).value
		self.unk22 = PVOID(reader).value
		self.unk23 = ULONG(reader).value
		reader.align()
		self.CredentialManager = PVOID(reader)


class PKIWI_MSV1_0_LIST_52(POINTER):
	def __init__(self, reader):
		super(PKIWI_MSV1_0_LIST_52, self).__init__(reader, KIWI_MSV1_0_LIST_52)
		

class KIWI_MSV1_0_LIST_52:
	def __init__(self, reader):
		self.Flink = PKIWI_MSV1_0_LIST_52(reader)
		self.Blink = PKIWI_MSV1_0_LIST_52(reader)
		self.LocallyUniqueIdentifier = LUID
		self.UserName = LSA_UNICODE_STRING(reader)
		self.Domaine = LSA_UNICODE_STRING(reader)
		self.unk0 = PVOID(reader).value
		self.unk1 = PVOID(reader).value
		self.pSid = PSID(reader)
		self.LogonType = ULONG(reader).value
		self.Session = ULONG(reader).value
		reader.align()
		self.LogonTime = struct.unpack("<Q", reader.read(8))[0]  # autoalign x86
		self.LogonServer = LSA_UNICODE_STRING(reader)
		self.Credentials_list_ptr = PKIWI_MSV1_0_CREDENTIAL_LIST(reader)
		self.unk19 = ULONG(reader).value
		reader.align()
		self.unk20 = PVOID(reader).value
		self.unk21 = PVOID(reader).value
		self.unk22 = ULONG(reader).value
		reader.align()
		self.CredentialManager = PVOID(reader)


class PKIWI_MSV1_0_LIST_60(POINTER):
	def __init__(self, reader):
		super(PKIWI_MSV1_0_LIST_60, self).__init__(reader, KIWI_MSV1_0_LIST_60)


class KIWI_MSV1_0_LIST_60:
	def __init__(self, reader):
		self.Flink = PKIWI_MSV1_0_LIST_60(reader)
		self.Blink = PKIWI_MSV1_0_LIST_60(reader)
		reader.align()
		self.unk0 = PVOID(reader).value
		self.unk1 = ULONG(reader).value
		reader.align()
		self.unk2 = PVOID(reader).value
		self.unk3 = ULONG(reader).value
		self.unk4 = ULONG(reader).value
		self.unk5 = ULONG(reader).value
		reader.align()
		self.hSemaphore6 = HANDLE(reader).value
		reader.align()
		self.unk7 = PVOID(reader).value
		reader.align()
		self.hSemaphore8 = HANDLE(reader).value
		reader.align()
		self.unk9 = PVOID(reader).value
		reader.align()
		self.unk10 = PVOID(reader).value
		self.unk11 = ULONG(reader).value
		self.unk12 = ULONG(reader).value
		reader.align()
		self.unk13 = PVOID(reader).value
		reader.align()
		self.LocallyUniqueIdentifier = struct.unpack("<Q", reader.read(8))[0]
		self.SecondaryLocallyUniqueIdentifier = struct.unpack("<Q", reader.read(8))[0]
		reader.align()
		self.UserName = LSA_UNICODE_STRING(reader)
		self.Domaine = LSA_UNICODE_STRING(reader)
		self.unk14 = PVOID(reader).value
		self.unk15 = PVOID(reader).value
		self.pSid = PSID(reader)
		self.LogonType = ULONG(reader).value
		self.Session = ULONG(reader).value
		reader.align(8)
		self.LogonTime = struct.unpack("<Q", reader.read(8))[0]  # autoalign x86
		self.LogonServer = LSA_UNICODE_STRING(reader)
		self.Credentials_list_ptr = PKIWI_MSV1_0_CREDENTIAL_LIST(reader)
		self.unk19 = ULONG(reader).value
		reader.align()
		self.unk20 = PVOID(reader).value
		self.unk21 = PVOID(reader).value
		self.unk22 = PVOID(reader).value
		self.unk23 = ULONG(reader).value
		reader.align()
		self.CredentialManager = PVOID(reader)


class PKIWI_MSV1_0_LIST_61(POINTER):
	def __init__(self, reader):
		super(PKIWI_MSV1_0_LIST_61, self).__init__(reader, KIWI_MSV1_0_LIST_61)


class KIWI_MSV1_0_LIST_61:
	def __init__(self, reader):
		
		self.Flink = PKIWI_MSV1_0_LIST_61(reader)
		self.Blink = PKIWI_MSV1_0_LIST_61(reader)
		self.unk0 = PVOID(reader).value
		self.unk1 = ULONG(reader).value
		reader.align()
		self.unk2 = PVOID(reader).value
		self.unk3 = ULONG(reader).value
		self.unk4 = ULONG(reader).value
		self.unk5 = ULONG(reader).value
		reader.align()
		self.hSemaphore6 = HANDLE(reader).value
		self.unk7 = PVOID(reader).value
		self.hSemaphore8 = HANDLE(reader).value
		self.unk9 = PVOID(reader).value
		self.unk10 = PVOID(reader).value
		self.unk11 = ULONG(reader).value
		self.unk12 = ULONG(reader).value
		self.unk13 = PVOID(reader).value
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.SecondaryLocallyUniqueIdentifier = LUID(reader).value
		self.UserName = LSA_UNICODE_STRING(reader)
		self.Domaine = LSA_UNICODE_STRING(reader)
		self.unk14 = PVOID(reader).value
		self.unk15 = PVOID(reader).value
		self.pSid = PSID(reader)
		self.LogonType = ULONG(reader).value
		self.Session = ULONG(reader).value
		reader.align(8)
		self.LogonTime = struct.unpack("<Q", reader.read(8))[0]  # autoalign x86
		self.LogonServer = LSA_UNICODE_STRING(reader)
		self.Credentials_list_ptr = PKIWI_MSV1_0_CREDENTIAL_LIST(reader)
		self.unk19 = PVOID(reader).value
		self.unk20 = PVOID(reader).value
		self.unk21 = PVOID(reader).value
		self.unk22 = ULONG(reader).value
		reader.align()
		self.CredentialManager = PVOID(reader)


class PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ(POINTER):
	def __init__(self, reader):
		super(PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ, self).__init__(reader, KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ)	


class KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ:
	def __init__(self, reader):
		self.Flink = PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ(reader)
		self.Blink = PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ(reader)
		self.unk0 = PVOID(reader).value
		self.unk1 = ULONG(reader).value
		reader.align()
		self.unk2 = PVOID(reader).value
		self.unk3 = ULONG(reader).value
		self.unk4 = ULONG(reader).value
		self.unk5 = ULONG(reader).value
		reader.align()
		self.hSemaphore6 = HANDLE(reader).value
		self.unk7 = PVOID(reader).value
		self.hSemaphore8 = HANDLE(reader).value
		self.unk9 = PVOID(reader).value
		self.unk10 = PVOID(reader).value
		self.unk11 = ULONG(reader).value
		self.unk12 = ULONG(reader).value
		self.unk13 = PVOID(reader).value
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.SecondaryLocallyUniqueIdentifier = LUID(reader).value
		self.waza = reader.read(12)
		reader.align()
		self.UserName = LSA_UNICODE_STRING(reader)
		self.Domaine = LSA_UNICODE_STRING(reader)
		self.unk14 = PVOID(reader).value
		self.unk15 = PVOID(reader).value
		self.pSid = PSID(reader)
		self.LogonType = ULONG(reader).value
		self.Session = ULONG(reader).value
		reader.align(8)
		self.LogonTime = struct.unpack("<Q", reader.read(8))[0]  # autoalign x86
		self.LogonServer = LSA_UNICODE_STRING(reader)
		self.Credentials_list_ptr = PKIWI_MSV1_0_CREDENTIAL_LIST(reader)
		self.unk19 = PVOID(reader).value
		self.unk20 = PVOID(reader).value
		self.unk21 = PVOID(reader).value
		self.unk22 = ULONG(reader).value
		reader.align()
		self.CredentialManager = PVOID(reader)


class PKIWI_MSV1_0_LIST_62(POINTER):
	def __init__(self, reader):
		super(PKIWI_MSV1_0_LIST_62, self).__init__(reader, KIWI_MSV1_0_LIST_62)	


class KIWI_MSV1_0_LIST_62:
	def __init__(self, reader):
		self.Flink = PKIWI_MSV1_0_LIST_62(reader)
		self.Blink = PKIWI_MSV1_0_LIST_62(reader)
		self.unk0 = PVOID(reader).value
		self.unk1 = ULONG(reader).value
		reader.align()
		self.unk2 = PVOID(reader).value
		self.unk3 = ULONG(reader).value
		self.unk4 = ULONG(reader).value
		self.unk5 = ULONG(reader).value
		reader.align()
		self.hSemaphore6 = HANDLE(reader).value
		self.unk7 = PVOID(reader).value
		self.hSemaphore8 = HANDLE(reader).value
		self.unk9 = PVOID(reader).value
		self.unk10 = PVOID(reader).value
		self.unk11 = ULONG(reader).value
		self.unk12 = ULONG(reader).value
		self.unk13 = PVOID(reader).value
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.SecondaryLocallyUniqueIdentifier = LUID(reader).value
		self.UserName = LSA_UNICODE_STRING(reader)
		self.Domaine = LSA_UNICODE_STRING(reader)
		self.unk14 = PVOID(reader).value
		self.unk15 = PVOID(reader).value
		self.Type = LSA_UNICODE_STRING(reader)
		self.pSid = PSID(reader)
		self.LogonType = ULONG(reader).value
		reader.align()
		self.unk18 = PVOID(reader).value
		self.Session = ULONG(reader).value
		reader.align()
		self.LogonTime = struct.unpack("<Q", reader.read(8))[0]  # autoalign x86
		self.LogonServer = LSA_UNICODE_STRING(reader)
		self.Credentials_list_ptr = PKIWI_MSV1_0_CREDENTIAL_LIST(reader)
		self.unk19 = PVOID(reader).value
		self.unk20 = PVOID(reader).value
		self.unk21 = PVOID(reader).value
		self.unk22 = ULONG(reader).value
		self.unk23 = ULONG(reader).value
		self.unk24 = ULONG(reader).value
		self.unk25 = ULONG(reader).value
		self.unk26 = ULONG(reader).value
		reader.align()
		self.unk27 = PVOID(reader).value
		self.unk28 = PVOID(reader).value
		self.unk29 = PVOID(reader).value
		self.CredentialManager = PVOID(reader)


class PKIWI_MSV1_0_LIST_63(POINTER):
	def __init__(self, reader):
		super(PKIWI_MSV1_0_LIST_63, self).__init__(reader, KIWI_MSV1_0_LIST_63)


class KIWI_MSV1_0_LIST_63:
	def __init__(self, reader):
		self.Flink = PKIWI_MSV1_0_LIST_63(reader)
		self.Blink = PKIWI_MSV1_0_LIST_63(reader)
		self.unk0 = PVOID(reader).value
		self.unk1 = ULONG(reader).value
		reader.align()
		self.unk2 = PVOID(reader).value
		self.unk3 = ULONG(reader).value
		self.unk4 = ULONG(reader).value
		self.unk5 = ULONG(reader).value
		reader.align()
		self.hSemaphore6 = HANDLE(reader).value
		self.unk7 = PVOID(reader).value
		self.hSemaphore8 = HANDLE(reader).value
		self.unk9 = PVOID(reader).value
		self.unk10 = PVOID(reader).value
		self.unk11 = ULONG(reader).value
		self.unk12 = ULONG(reader).value
		self.unk13 = PVOID(reader).value
		reader.align()
		self.LocallyUniqueIdentifier = LUID(reader).value
		self.SecondaryLocallyUniqueIdentifier = LUID(reader).value
		self.waza = reader.read(12)
		reader.align()
		self.UserName = LSA_UNICODE_STRING(reader)
		self.Domaine = LSA_UNICODE_STRING(reader)
		self.unk14 = PVOID(reader).value
		self.unk15 = PVOID(reader).value
		self.Type = LSA_UNICODE_STRING(reader)
		self.pSid = PSID(reader)
		self.LogonType = ULONG(reader).value
		reader.align()
		self.unk18 = PVOID(reader).value
		self.Session = ULONG(reader).value
		reader.align(8)
		self.LogonTime = struct.unpack("<Q", reader.read(8))[0]  # autoalign x86
		self.LogonServer = LSA_UNICODE_STRING(reader)
		self.Credentials_list_ptr = PKIWI_MSV1_0_CREDENTIAL_LIST(reader)
		self.unk19 = PVOID(reader).value
		self.unk20 = PVOID(reader).value
		self.unk21 = PVOID(reader).value
		self.unk22 = ULONG(reader).value
		self.unk23 = ULONG(reader).value
		self.unk24 = ULONG(reader).value
		self.unk25 = ULONG(reader).value
		self.unk26 = ULONG(reader).value
		reader.align()
		# input('CredentialManager\n' + hexdump(reader.peek(0x100)))
		self.unk27 = PVOID(reader).value
		self.unk28 = PVOID(reader).value
		self.unk29 = PVOID(reader).value
		self.CredentialManager = PVOID(reader)
