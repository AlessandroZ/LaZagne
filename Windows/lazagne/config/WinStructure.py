# Vault Structure has been taken from mimikatz
from ctypes.wintypes import *
from ctypes import *

LPTSTR 					= LPSTR
LPCTSTR 				= LPSTR
PHANDLE 				= POINTER(HANDLE)
HANDLE      			= LPVOID
LPDWORD   				= POINTER(DWORD)
INVALID_HANDLE_VALUE 	= c_void_p(-1).value
NTSTATUS 				= ULONG()
PWSTR					= c_wchar_p
LPWSTR 					= c_wchar_p
PBYTE 					= POINTER(BYTE)
LPBYTE 					= POINTER(BYTE)


vaultcli = windll.vaultcli
kernel32 = windll.kernel32

##############################- Constants ##############################

# Credential Manager
CRYPTPROTECT_UI_FORBIDDEN 			= 0x01
CRED_TYPE_GENERIC 					= 0x1
CRED_TYPE_DOMAIN_VISIBLE_PASSWORD	= 0x4

# Regedit 
HKEY_CURRENT_USER 					= -2147483647
KEY_READ 							= 131097
KEY_ENUMERATE_SUB_KEYS				= 8
KEY_QUERY_VALUE						= 1

# custom key to read registry (not from msdn)
ACCESS_READ = KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE 

############################## Structures ##############################

class CREDENTIAL_ATTRIBUTE(Structure):
	_fields_ = [
		('Keyword', LPSTR),
		('Flags', DWORD),
		('ValueSize', DWORD),
		('Value', LPBYTE)
	]
PCREDENTIAL_ATTRIBUTE = POINTER(CREDENTIAL_ATTRIBUTE)

class CREDENTIAL(Structure):
	_fields_ = [
		('Flags', DWORD),
		('Type', DWORD),
		('TargetName', LPSTR),
		('Comment', LPSTR),
		('LastWritten', FILETIME),
		('CredentialBlobSize', DWORD),
		# ('CredentialBlob', POINTER(BYTE)),
		('CredentialBlob', POINTER(c_char)),
		('Persist', DWORD),
		('AttributeCount', DWORD),
		('Attributes', PCREDENTIAL_ATTRIBUTE),
		('TargetAlias', LPSTR),
		('UserName', LPSTR)
	]
PCREDENTIAL = POINTER(CREDENTIAL)

class DATA_BLOB(Structure):
	_fields_ = [
		('cbData', DWORD),
		('pbData', POINTER(c_char))
	]

class GUID(Structure):
	_fields_ = [
		("data1", DWORD),
		("data2", WORD),
		("data3", WORD),
		("data4", BYTE * 6)
	]
LPGUID = POINTER(GUID)

class VAULT_CREDENTIAL_ATTRIBUTEW(Structure):
	_fields_ = [
		('keyword', 		LPWSTR),
		('flags', 			DWORD),
		('badAlign', 		DWORD),
		('valueSize', 		DWORD),
		('value', 			LPBYTE),
	]
PVAULT_CREDENTIAL_ATTRIBUTEW = POINTER(VAULT_CREDENTIAL_ATTRIBUTEW)

class VAULT_BYTE_BUFFER(Structure):
	_fields_ = [
		('length', 		DWORD),
		('value', 		PBYTE),
	]

class DATA(Structure):
	_fields_ = [
		# ('boolean', 		BOOL),
		# ('short', 			SHORT),
		# ('unsignedShort', 	WORD),
		# ('int', 			LONG),
		# ('unsignedInt', 	ULONG),
		# ('double', 			DOUBLE),
		('guid', 			GUID),
		('string', 			LPWSTR),
		('byteArray', 		VAULT_BYTE_BUFFER),
		('protectedArray', 	VAULT_BYTE_BUFFER),
		('attribute', 		PVAULT_CREDENTIAL_ATTRIBUTEW),
		# ('Sid', 			PSID)
		('sid', 			DWORD)
	]

class Flag(Structure):
	_fields_ = [
		('0x00', DWORD),
		('0x01', DWORD),
		('0x02', DWORD),
		('0x03', DWORD),
		('0x04', DWORD),
		('0x05', DWORD),
		('0x06', DWORD),
		('0x07', DWORD),
		('0x08', DWORD),
		('0x09', DWORD),
		('0x0a', DWORD),
		('0x0b', DWORD),
		('0x0c', DWORD),
		('0x0d', DWORD)
    ]

class VAULT_ITEM_DATA(Structure):
	_fields_ = [
		# ('schemaElementId', 	DWORD),
		# ('unk0', 				DWORD),
		# ('Type', 				VAULT_ELEMENT_TYPE),
		# ('type', 				Flag),
		# ('type', 				DWORD * 14),
		# ('unk1', 				DWORD),
		('data', 				DATA),
	]
PVAULT_ITEM_DATA = POINTER(VAULT_ITEM_DATA)

class VAULT_ITEM_WIN8(Structure):
	_fields_ = [
		('id', 				GUID),
		('pName', 			PWSTR),
		('pResource', 		PVAULT_ITEM_DATA),
		('pUsername', 		PVAULT_ITEM_DATA),
		('pPassword', 		PVAULT_ITEM_DATA), 
		('unknown0', 		PVAULT_ITEM_DATA), 
		('LastWritten', 	FILETIME), 
		('Flags', 			DWORD), 
		('cbProperties', 	DWORD), 
		('Properties', 		PVAULT_ITEM_DATA), 
	]
PVAULT_ITEM_WIN8 = POINTER(VAULT_ITEM_WIN8)

# class VAULT_ITEM_WIN7(Structure):
# 	_fields_ = [
# 		('id', 				GUID),
# 		('pName', 			PWSTR),
# 		('pResource', 		PVAULT_ITEM_DATA),
# 		('pUsername', 		PVAULT_ITEM_DATA),
# 		('pPassword', 		PVAULT_ITEM_DATA), 
# 		('LastWritten', 	FILETIME), 
# 		('Flags', 			DWORD),  
# 		('cbProperties', 	DWORD),
# 		('Properties', 		PVAULT_ITEM_DATA),
# 	]
# PVAULT_ITEM_WIN7 = POINTER(VAULT_ITEM_WIN7)

class OSVERSIONINFOEXW(Structure):
	_fields_ = [
		('dwOSVersionInfoSize', c_ulong),
		('dwMajorVersion', c_ulong),
		('dwMinorVersion', c_ulong),
		('dwBuildNumber', c_ulong),
		('dwPlatformId', c_ulong),
		('szCSDVersion', c_wchar*128),
		('wServicePackMajor', c_ushort),
		('wServicePackMinor', c_ushort),
		('wSuiteMask', c_ushort),
		('wProductType', c_byte),
		('wReserved', c_byte)
	]

############################## Functions ##############################

CredEnumerate 			= windll.advapi32.CredEnumerateA
CredEnumerate.restype 	= BOOL
CredEnumerate.argtypes 	= [LPCTSTR, DWORD, POINTER(DWORD), POINTER(POINTER(PCREDENTIAL))]
 
CredFree 				= windll.advapi32.CredFree
CredFree.restype 		= c_void_p
CredFree.argtypes 		= [c_void_p]

memcpy 					= cdll.msvcrt.memcpy
LocalFree 				= windll.kernel32.LocalFree
CryptUnprotectData 		= windll.crypt32.CryptUnprotectData


prototype = WINFUNCTYPE(ULONG, DWORD, LPDWORD, POINTER(LPGUID))
vaultEnumerateVaults = prototype(("VaultEnumerateVaults", windll.vaultcli))

prototype = WINFUNCTYPE(ULONG, LPGUID, DWORD, HANDLE)
vaultOpenVault = prototype(("VaultOpenVault", windll.vaultcli))

prototype = WINFUNCTYPE(ULONG, HANDLE, DWORD, LPDWORD, POINTER(c_char_p))
vaultEnumerateItems = prototype(("VaultEnumerateItems", windll.vaultcli))

prototype = WINFUNCTYPE(ULONG, HANDLE, LPGUID, PVAULT_ITEM_DATA, PVAULT_ITEM_DATA, PVAULT_ITEM_DATA, HWND, DWORD, POINTER(PVAULT_ITEM_WIN8))
vaultGetItem8 = prototype(("VaultGetItem", windll.vaultcli))

# prototype = WINFUNCTYPE(ULONG, HANDLE, LPGUID, PVAULT_ITEM_DATA, PVAULT_ITEM_DATA, HWND, DWORD, POINTER(PVAULT_ITEM_WIN7))
# vaultGetItem7 = prototype(("VaultGetItem", windll.vaultcli))

prototype = WINFUNCTYPE(ULONG, LPVOID)
vaultFree = prototype(("VaultFree", windll.vaultcli))

prototype = WINFUNCTYPE(ULONG, PHANDLE)
vaultCloseVault = prototype(("VaultCloseVault", windll.vaultcli))


############################## Custom functions ##############################

def getData(blobOut):
		cbData = int(blobOut.cbData)
		pbData = blobOut.pbData
		buffer = c_buffer(cbData)
		
		memcpy(buffer, pbData, cbData)
		LocalFree(pbData);
		return buffer.raw

def Win32CryptUnprotectData(cipherText, entropy=None):
	bufferIn 	= c_buffer(str(cipherText), len(cipherText))
	blobIn 		= DATA_BLOB(len(cipherText), bufferIn)
	blobOut 	= DATA_BLOB()

	if entropy:
		bufferEntropy 	= c_buffer(entropy, len(entropy))
		blobEntropy 	= DATA_BLOB(len(entropy), bufferEntropy)

		if CryptUnprotectData(byref(blobIn), None, byref(blobEntropy), None, None, 0, byref(blobOut)):
			return getData(blobOut)
		else:
			return False
	
	else:
		if CryptUnprotectData(byref(blobIn), None, None, None, None, 0, byref(blobOut)):
			return getData(blobOut)
		else:
			return False

# return major anr minor version
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
def get_os_version():
	os_version = OSVERSIONINFOEXW()
	os_version.dwOSVersionInfoSize = sizeof(os_version)
	retcode = windll.Ntdll.RtlGetVersion(byref(os_version))
	if retcode != 0:
		return False

	return '%s.%s' % (str(os_version.dwMajorVersion.real), str(os_version.dwMinorVersion.real))