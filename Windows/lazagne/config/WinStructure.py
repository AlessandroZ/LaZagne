from ctypes.wintypes import *
from ctypes import *

LPBYTE 		= POINTER(BYTE)
LPTSTR 		= LPSTR
LPCTSTR 	= LPSTR

# ------------------ Constants ------------------

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

# ------------------ Structures ------------------

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

# ------------------ Functions ------------------

CredEnumerate 			= windll.advapi32.CredEnumerateA
CredEnumerate.restype 	= BOOL
CredEnumerate.argtypes 	= [LPCTSTR, DWORD, POINTER(DWORD), POINTER(POINTER(PCREDENTIAL))]
 
CredFree 				= windll.advapi32.CredFree
CredFree.restype 		= c_void_p
CredFree.argtypes 		= [c_void_p]

memcpy 					= cdll.msvcrt.memcpy
LocalFree 				= windll.kernel32.LocalFree
CryptUnprotectData 		= windll.crypt32.CryptUnprotectData


# ------------------ Custom functions ------------------

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