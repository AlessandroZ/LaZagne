from .version import GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO, ERROR_BAD_LENGTH, ERROR_BAD_ARGUMENTS
import ctypes


def get_file_version_info(filename):
	# Get the file version info structure.
	pBlock = GetFileVersionInfoW(filename)
	pBuffer, dwLen = VerQueryValueW(pBlock.raw, "\\")
	if dwLen != ctypes.sizeof(VS_FIXEDFILEINFO):
		raise ctypes.WinError(ERROR_BAD_LENGTH)
	pVersionInfo = ctypes.cast(pBuffer, ctypes.POINTER(VS_FIXEDFILEINFO))
	VersionInfo = pVersionInfo.contents
	if VersionInfo.dwSignature != 0xFEEF04BD:
		raise ctypes.WinError(ERROR_BAD_ARGUMENTS)

	FileDate = (VersionInfo.dwFileDateMS << 32) + VersionInfo.dwFileDateLS
	return FileDate
