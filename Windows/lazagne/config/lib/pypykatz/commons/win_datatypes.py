#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
import enum
import struct


class POINTER(object):
	__slots__ = (
		'location', 'value', 'finaltype'
	)

	def __init__(self, reader, finaltype):
		self.location = reader.tell()
		self.value = reader.read_uint()
		self.finaltype = finaltype

	def read(self, reader, override_finaltype=None):
		if self.value == 0:
			return None
		pos = reader.tell()
		reader.move(self.value)
		if override_finaltype:
			data = override_finaltype(reader)
		else:
			data = self.finaltype(reader)
		reader.move(pos)
		return data

	def read_raw(self, reader, size):
		# we do not know the finaltype, just want the data
		if self.value == 0:
			return None
		pos = reader.tell()
		reader.move(self.value)
		data = reader.read(size)
		reader.move(pos)
		return data


class PVOID(POINTER):
	def __init__(self, reader):
		super(PVOID, self).__init__(reader, None)  # with void we cannot determine the final type


class VALUE(object):
	__slots__ = ('value',)

	def __init__(self, value):
		self.value = value


class BOOL(VALUE):
	__slots__= ()

	def __init__(self, reader):
		super(BOOL, self).__init__(bool(reader.read_uint()))


class BOOLEAN(VALUE):
	__slots__= ()

	def __init__(self, reader):
		super(BOOLEAN, self).__init__(reader.read(1))


class BYTE(VALUE):
	__slots__= ()

	def __init__(self, reader):
		super(BYTE, self).__init__(reader.read(1))


class PBYTE(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(PBYTE, self).__init__(reader, BYTE)


class CCHAR(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(CCHAR, self).__init__(reader.read(1).decode('ascii'))


class CHAR(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(CHAR, self).__init__(reader.read(1).decode('ascii'))


class UCHAR(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(UCHAR, self).__init__(ord(reader.read(1)))


class WORD(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(WORD, self).__init__(
			struct.unpack("<H", reader.read(2))[0])


class DWORD(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(DWORD, self).__init__(
			struct.unpack("<L", reader.read(4))[0])


class DWORDLONG(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(DWORDLONG, self).__init__(
			struct.unpack("<Q", reader.read(8))[0])


class DWORD_PTR(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(DWORD_PTR, self).__init__(reader, DWORD)


class DWORD32(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(DWORD32, self).__init__(
			struct.unpack("<L", reader.read(4))[0])


class DWORD64(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(DWORD64, self).__init__(
			struct.unpack("<Q", reader.read(8))[0])


class HANDLE(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(HANDLE, self).__init__(
			reader.read_uint())


class HFILE(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(HFILE, self).__init___(
			struct.unpack("<L", reader.read(4))[0])


class HINSTANCE(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(HINSTANCE, self).__init__(
			reader.read_uint())


class HKEY(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(HKEY, self).__init__(reader.read_uint())


class HKL(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(HKL, self).__init__(reader.read_uint())


class HLOCAL(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(HLOCAL, self).__init__(reader.read_uint())


class INT(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(INT, self).__init__(reader.read_int())


class INT_PTR(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(INT_PTR, self).__init__(reader, INT)


class UINT8(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(UINT8, self).__init__(ord(reader.read(1)))


class INT8(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(INT8, self).__init__(ord(reader.read(1)))


class INT16(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(INT16, self).__init__(
			struct.unpack("<h", reader.read(2))[0])


class INT32(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(INT32, self).__init__(
			struct.unpack("<l", reader.read(4))[0])


class INT64(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(INT64, self).__init__(
			struct.unpack("<q", reader.read(8))[0])


class LONG(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(LONG, self).__init__(
			struct.unpack("<l", reader.read(4))[0])


class LONGLONG(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(LONGLONG, self).__init__(
			struct.unpack("<q", reader.read(8))[0])


class LONG_PTR(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(LONG_PTR, self).__init__(reader, LONG)


class LONG32(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(LONG32, self).__init__(
			struct.unpack("<q", reader.read(8))[0])


class LONG64(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(LONG64, self).__init__(
			struct.unpack("<q", reader.read(8))[0])


class LPARAM(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(LPARAM, self).__init__(reader, LONG)


class LPBOOL(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(LPBOOL, self).__init__(reader, BOOL)


class LPBYTE(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(LPBYTE, self).__init__(reader, BYTE)


class ULONG(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(ULONG, self).__init__(
			struct.unpack("<L", reader.read(4))[0])


class ULONGLONG(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(ULONGLONG, self.value).__init__(
			struct.unpack("<Q", reader.read(8))[0])


class ULONG32(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(ULONG32, self).__init__(
			struct.unpack("<L", reader.read(4))[0])


class ULONG64(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(ULONG64, self).__init__(
			struct.unpack("<Q", reader.read(8))[0])


class PWSTR(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(PWSTR, self).__init__(reader, None)


class PCHAR(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(PCHAR, self).__init__(reader, CHAR)


class USHORT(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(USHORT, self).__init__(
			struct.unpack("<H", reader.read(2))[0])


class SHORT(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(SHORT, self).__init__(
			struct.unpack("<h", reader.read(2))[0])


# https://msdn.microsoft.com/en-us/library/windows/hardware/ff554296(v=vs.85).aspx
class LIST_ENTRY(object):
	__slots__ = ('Flink', 'Blink')

	def __init__(self, reader, finaltype=None):
		self.Flink = POINTER(reader, finaltype)
		self.Blink = POINTER(reader, finaltype)


class FILETIME(object):
	__slots__ = (
		'dwLowDateTime', 'dwHighDateTime', 'value'
	)

	def __init__(self, reader):
		self.dwLowDateTime = DWORD(reader)
		self.dwHighDateTime = DWORD(reader)
		self.value = (
			self.dwHighDateTime.value << 32
		) + self.dwLowDateTime.value


class PUCHAR(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(PUCHAR, self).__init__(reader, UCHAR)


class PCWSTR(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(PCWSTR, self).__init__(reader, None)


class SIZE_T(VALUE):
	__slots__ = ()

	def __init__(self, reader):
		super(SIZE_T, self).__init__(reader.read_uint())


class LARGE_INTEGER(object):
	__slots__ = (
		'LowPart', 'HighPart', 'QuadPart'
	)

	def __init__(self, reader):
		self.LowPart = DWORD(reader).value
		self.HighPart = LONG(reader).value
		self.QuadPart = LONGLONG(reader).value


class PSID(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(PSID, self).__init__(reader, SID)


class SID(object):
	__slots__ = (
		'Revision', 'SubAuthorityCount',
		'IdentifierAuthority', 'SubAuthority'
	)

	def __init__(self, reader):
		self.Revision = UINT8(reader).value
		self.SubAuthorityCount = UINT8(reader).value
		self.IdentifierAuthority = struct.unpack(
			">Q", b'\x00\x00' + reader.read(6))[0]
		self.SubAuthority = []
		for i in range(self.SubAuthorityCount):
			self.SubAuthority.append(ULONG(reader).value)
	
	def __str__(self):
		t = 'S-%d-%d' % (self.Revision, self.IdentifierAuthority)
		for subauthority in self.SubAuthority:
			t += '-%d' % subauthority
		return t


class LUID(object):
	__slots__ = (
		'LowPart', 'HighPart', 'value'
	)

	def __init__(self, reader):
		self.LowPart = DWORD(reader).value
		self.HighPart = LONG(reader).value
		self.value = (self.HighPart << 32) + self.LowPart


# https://msdn.microsoft.com/en-us/library/windows/desktop/ms721841(v=vs.85).aspx
class LSA_UNICODE_STRING(object):
	__slots__ = (
		'Length', 'MaximumLength', 'Buffer'
	)

	def __init__(self, reader):
		self.Length = USHORT(reader).value
		self.MaximumLength = USHORT(reader).value
		reader.align()
		self.Buffer = PWSTR(reader).value
		
	def read_string(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return ''
		reader.move(self.Buffer)
		data = reader.read(self.Length)
		data_str = data.decode('utf-16-le').rstrip('\0')
		return data_str
		
	def read_data(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return b''
		reader.move(self.Buffer)
		return reader.read(self.Length)
		
	def read_maxdata(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return b''
		reader.move(self.Buffer)
		return reader.read(self.MaximumLength)


# https://msdn.microsoft.com/en-us/library/windows/hardware/ff540605(v=vs.85).aspx
class PANSI_STRING(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(PANSI_STRING, self).__init__(reader, ANSI_STRING)


class ANSI_STRING(object):
	__slots__ = (
		'Length', 'MaximumLength', 'Buffer'
	)

	def __init__(self, reader):
		self.Length = USHORT(reader)
		self.MaximumLength = USHORT(reader)
		# reader.align()
		self.Buffer = PCHAR(reader).value
		
	def read_string(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return ''
		reader.move(self.Buffer)
		data = reader.read(self.Length)
		data_str = data.decode().rstrip('\0')
		return data_str
		
	def read_data(self, reader):
		if self.Buffer == 0 or self.Length == 0:
			return b''
		reader.move(self.Buffer)
		return reader.read(self.Length)

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa378064(v=vs.85).aspx


class KerberosNameType(enum.Enum):
	__slots__ = ()

	KRB_NT_UNKNOWN = 0
	KRB_NT_PRINCIPAL = 1
	KRB_NT_PRINCIPAL_AND_ID = -131
	KRB_NT_SRV_INST = 2
	KRB_NT_SRV_INST_AND_ID = -132
	KRB_NT_SRV_HST = 3
	KRB_NT_SRV_XHST = 4
	KRB_NT_UID = 5
	KRB_NT_ENTERPRISE_PRINCIPAL = 10
	KRB_NT_ENT_PRINCIPAL_AND_ID = -130
	KRB_NT_MS_PRINCIPAL = -128
	KRB_NT_MS_PRINCIPAL_AND_ID = -129


class PKERB_EXTERNAL_NAME(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(PKERB_EXTERNAL_NAME, self).__init__(reader, KERB_EXTERNAL_NAME)


class KERB_EXTERNAL_NAME(object):
	__slots__ = (
		'NameType', 'NameCount', 'Names'
	)

	def __init__(self, reader):
		self.NameType = SHORT(reader).value # KerberosNameType(SHORT(reader).value)
		self.NameCount = USHORT(reader).value
		reader.align()
		self.Names = []	# list of LSA_UNICODE_STRING
		for i in range(self.NameCount):
			self.Names.append(LSA_UNICODE_STRING(reader))
		
	def read(self, reader):
		t = []
		for name in self.Names:
			t.append(name.read_string(reader))
		return t
		

class KIWI_GENERIC_PRIMARY_CREDENTIAL(object):
	__slots__ = (
		'UserName', 'Domaine', 'Password'
	)

	def __init__(self, reader):
		self.UserName = LSA_UNICODE_STRING(reader)
		self.Domaine = LSA_UNICODE_STRING(reader)
		self.Password = LSA_UNICODE_STRING(reader)


class PRTL_BALANCED_LINKS(POINTER):
	__slots__ = ()

	def __init__(self, reader):
		super(PRTL_BALANCED_LINKS, self).__init__(
			reader, RTL_BALANCED_LINKS)


class RTL_BALANCED_LINKS(object):
	__slots__ = (
		'Parent', 'LeftChild', 'RightChild',
		'Balance', 'Reserved'
	)

	def __init__(self, reader):
		self.Parent = PRTL_BALANCED_LINKS(reader)
		self.LeftChild = PRTL_BALANCED_LINKS(reader)
		self.RightChild = PRTL_BALANCED_LINKS(reader)
		self.Balance = BYTE(reader).value
		self.Reserved = reader.read(3)  # // align
		reader.align()


class PRTL_AVL_TABLE(POINTER):
	def __init__(self, reader):
		super(PRTL_AVL_TABLE, self).__init__(reader, RTL_AVL_TABLE)


class RTL_AVL_TABLE(object):
	__slots__ = (
		'BalancedRoot', 'OrderedPointer', 'WhichOrderedElement',
		'NumberGenericTableElements', 'DepthOfTree',
		'RestartKey', 'DeleteCount',
		'CompareRoutine', 'AllocateRoutine', 'FreeRoutine',
		'TableContext'
	)

	def __init__(self, reader):
		self.BalancedRoot = RTL_BALANCED_LINKS(reader)
		self.OrderedPointer = PVOID(reader)
		self.WhichOrderedElement = ULONG(reader).value
		self.NumberGenericTableElements = ULONG(reader).value
		self.DepthOfTree = ULONG(reader).value
		reader.align()
		self.RestartKey = PRTL_BALANCED_LINKS(reader)
		self.DeleteCount = ULONG(reader).value
		reader.align()
		self.CompareRoutine = PVOID (reader)
		self.AllocateRoutine = PVOID(reader)
		self.FreeRoutine = PVOID(reader)
		self.TableContext = PVOID(reader)


class PLSAISO_DATA_BLOB(POINTER):
	def __init__(self, reader):
		super(PLSAISO_DATA_BLOB, self).__init__(
			reader, LSAISO_DATA_BLOB)


class LSAISO_DATA_BLOB(object):
	# +sizeof array ? ANYSIZE_ARRAY
	size = 9*4 + 3*16 + 16

	__slots__ = (
		'structSize', 'unk0', 'typeSize',
		'unk1', 'unk2', 'unk3', 'unk4',
		'unkKeyData', 'unkData2', 'unk5',
		'origSize', 'data'
	)

	def __init__(self, reader):
		self.structSize = DWORD(reader)
		self.unk0 = DWORD(reader)
		self.typeSize = DWORD(reader)
		self.unk1 = DWORD(reader)
		self.unk2 = DWORD(reader)
		self.unk3 = DWORD(reader)
		self.unk4 = DWORD(reader)
		self.unkKeyData = reader.read(3*16)
		self.unkData2 = reader.read(16)
		self.unk5 = DWORD(reader)
		self.origSize = DWORD(reader)
		self.data = None # size determined later


class ENC_LSAISO_DATA_BLOB(object):
	__slots__ = (
		'unkData1', 'unkData2', 'data'
	)

	def __init__(self, reader):
		self.unkData1 = reader.read(16)
		self.unkData2 = reader.read(16)
		self.data = None  # size determined later


class GUID(object):
	__slots__ = (
		'Data1', 'Data2', 'Data3', 'Data4',
		'value'
	)

	def __init__(self, reader):
		self.Data1 = DWORD(reader).value
		self.Data2 = WORD(reader).value
		self.Data3 = WORD(reader).value
		self.Data4 = reader.read(8)
		
		self.value = '-'.join([
			hex(self.Data1)[2:], 
			hex(self.Data2)[2:], 
			hex(self.Data3)[2:], 
			hex(struct.unpack(">L", self.Data4[:4])[0])[2:],
			hex(struct.unpack(">L", self.Data4[4:])[0])[2:]
		])
