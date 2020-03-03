#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
from ..commons.win_datatypes import ULONG, PVOID, POINTER
from ..commons.common import KatzSystemArchitecture, WindowsMinBuild, WindowsBuild
from .package_commons import PackageTemplate


class LsaTemplate(PackageTemplate):
	def __init__(self):
		super(LsaTemplate, self).__init__('LSA Decryptor')
		self.key_pattern = None
		self.key_handle_struct = None
		self.key_struct = None
		self.hard_key_struct = KIWI_HARD_KEY
		
	@staticmethod
	def get_template(sysinfo):
		template = LsaTemplate()
		
		if sysinfo.architecture == KatzSystemArchitecture.X86:
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_XP.value:
				raise Exception("Maybe implemented later")
			
			elif sysinfo.buildnumber <= WindowsMinBuild.WIN_2K3.value:
				raise Exception("Maybe implemented later")
				
			elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 5
				key_pattern.offset_to_DES_key_ptr = -76
				key_pattern.offset_to_AES_key_ptr = -21
				
				template.key_pattern = key_pattern
				template.key_struct = KIWI_BCRYPT_KEY
				template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
			elif WindowsMinBuild.WIN_7.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 5
				key_pattern.offset_to_DES_key_ptr = -76
				key_pattern.offset_to_AES_key_ptr = -21
				
				template.key_pattern = key_pattern
				template.key_struct = KIWI_BCRYPT_KEY
				template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
			elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 5
				key_pattern.offset_to_DES_key_ptr = -69
				key_pattern.offset_to_AES_key_ptr = -18
				
				template.key_pattern = key_pattern
				template.key_struct = KIWI_BCRYPT_KEY8
				template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
			elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_10.value:
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 5
				
				key_pattern.offset_to_DES_key_ptr = -69
				key_pattern.offset_to_AES_key_ptr = -18
				
				template.key_pattern = key_pattern
				template.key_struct = KIWI_BCRYPT_KEY81
				template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
			elif WindowsMinBuild.WIN_10.value <= sysinfo.buildnumber <= WindowsBuild.WIN_10_1507.value:
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 5
				key_pattern.offset_to_DES_key_ptr = -79
				key_pattern.offset_to_AES_key_ptr = -22
				
				template.key_pattern = key_pattern
				template.key_struct = KIWI_BCRYPT_KEY81
				template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

			elif sysinfo.buildnumber > WindowsBuild.WIN_10_1507.value:
				
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x6a\x02\x6a\x10\x68'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 5
				key_pattern.offset_to_DES_key_ptr = -79
				key_pattern.offset_to_AES_key_ptr = -22
				
				template.key_pattern = key_pattern
				template.key_struct = KIWI_BCRYPT_KEY81
				template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
		
		elif sysinfo.architecture == KatzSystemArchitecture.X64:
		
			if sysinfo.buildnumber <= WindowsMinBuild.WIN_XP.value:
				raise Exception("Maybe implemented later")
			
			elif sysinfo.buildnumber <= WindowsMinBuild.WIN_2K3.value:
				raise Exception("Maybe implemented later")
			
			elif sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
				# vista
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 63
				key_pattern.offset_to_DES_key_ptr = -69
				key_pattern.offset_to_AES_key_ptr = 25
				
				template.key_pattern = key_pattern
				template.key_struct = KIWI_BCRYPT_KEY
				template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
		
			elif sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
				# win 7
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 59
				key_pattern.offset_to_DES_key_ptr = -61
				key_pattern.offset_to_AES_key_ptr = 25
				
				template.key_pattern = key_pattern
				template.key_struct = KIWI_BCRYPT_KEY
				template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
			
			elif sysinfo.buildnumber < WindowsMinBuild.WIN_10.value:
				# win 8 and blue
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x83\x64\x24\x30\x00\x44\x8b\x4d\xd8\x48\x8b\x0d'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 62
				key_pattern.offset_to_DES_key_ptr = -70
				key_pattern.offset_to_AES_key_ptr = 23
				
				if sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
					# win8
					template.key_pattern = key_pattern
					template.key_struct = KIWI_BCRYPT_KEY8
					template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY
				
				else:
					# win blue
					template.key_pattern = key_pattern
					template.key_struct = KIWI_BCRYPT_KEY81
					template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

			elif sysinfo.buildnumber <= WindowsBuild.WIN_10_1809.value:
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 61
				key_pattern.offset_to_DES_key_ptr = -73
				key_pattern.offset_to_AES_key_ptr = 16
				
				template.key_pattern = key_pattern
				template.key_struct = KIWI_BCRYPT_KEY81
				template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

			# elif sysinfo.buildnumber <= WindowsBuild.WIN_10_1809.value:
			else:
				# 1809
				key_pattern = LSADecyptorKeyPattern()
				key_pattern.signature = b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15'
				key_pattern.IV_length = 16
				key_pattern.offset_to_IV_ptr = 67
				key_pattern.offset_to_DES_key_ptr = -89
				key_pattern.offset_to_AES_key_ptr = 16
				
				template.key_pattern = key_pattern
				template.key_struct = KIWI_BCRYPT_KEY81
				template.key_handle_struct = KIWI_BCRYPT_HANDLE_KEY

		else:
			raise Exception('Missing LSA decrpytor template for Architecture: %s , Build number %s' % (sysinfo.architecture, sysinfo.buildnumber))
			
		template.log_template('key_handle_struct', template.key_handle_struct)
		template.log_template('key_struct', template.key_struct)
		template.log_template('hard_key_struct', template.hard_key_struct)
		
		return template


class LSADecyptorKeyPattern:
	def __init__(self):
		self.signature = None  # byte pattern that identifies the location of the key structures (AES and DES)
		# offset from pattern that gives the pointer to the IV (applicable for both keys, kept separately from key structures)
		self.offset_to_IV_ptr = None
		self.IV_length = None  # length of the IV, always 16 from NT6
		self.offset_to_AES_key_ptr = None  # offset from signature that gives the pointer to the DES key structure
		self.offset_to_DES_key_ptr = None  # offset from signature that gives the pointer to the AES key structure
	

class KIWI_HARD_KEY:
	def __init__(self, reader):
		self.cbSecret = ULONG(reader).value
		self.data = reader.read(self.cbSecret)


class KIWI_BCRYPT_KEY:
	def __init__(self, reader):
		self.size = ULONG(reader).value
		self.tag = reader.read(4)
		self.type = ULONG(reader).value
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = ULONG(reader).value
		self.hardkey = KIWI_HARD_KEY(reader)
		
	def verify(self):
		return self.tag == b'KSSM'


class KIWI_BCRYPT_KEY8:
	def __init__(self, reader):
		self.size = ULONG(reader).value
		self.tag  = reader.read(4)  # 'MSSK'
		self.type = ULONG(reader).value
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = ULONG(reader).value
		self.unk3 = ULONG(reader).value
		reader.align()
		self.unk4 = PVOID(reader).value	# before, align in x64
		self.hardkey = KIWI_HARD_KEY(reader)
		
	def verify(self):
		return self.tag == b'KSSM' 


class KIWI_BCRYPT_KEY81:
	def __init__(self, reader):
		self.size = ULONG(reader).value
		self.tag  = reader.read(4)  # 'MSSK'
		self.type = ULONG(reader).value
		self.unk0 = ULONG(reader).value
		self.unk1 = ULONG(reader).value
		self.unk2 = ULONG(reader).value 
		self.unk3 = ULONG(reader).value
		self.unk4 = ULONG(reader).value
		reader.align()
		self.unk5 = PVOID(reader).value	 # before, align in x64
		self.unk6 = ULONG(reader).value
		self.unk7 = ULONG(reader).value
		self.unk8 = ULONG(reader).value
		self.unk9 = ULONG(reader).value
		self.hardkey = KIWI_HARD_KEY(reader)

	def verify(self):
		return self.tag == b'KSSM' 


class PKIWI_BCRYPT_KEY(POINTER):
	def __init__(self, reader):
		super(PKIWI_BCRYPT_KEY, self).__init__(reader, KIWI_BCRYPT_KEY)


class KIWI_BCRYPT_HANDLE_KEY:
	def __init__(self, reader):
		self.size = ULONG(reader).value
		self.tag = reader.read(4)  # 'UUUR'
		self.hAlgorithm = PVOID(reader).value
		self.ptr_key = PKIWI_BCRYPT_KEY(reader)
		self.unk0 = PVOID(reader).value

	def verify(self):
		return self.tag == b'RUUU'
