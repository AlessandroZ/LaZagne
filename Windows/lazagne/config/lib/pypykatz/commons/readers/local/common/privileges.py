#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#

import ctypes
from ctypes import windll
from ctypes.wintypes import ULONG, BOOL, LONG

from .privileges_types import PrivilegeValues

STATUS_SUCCESS = 0
NTSTATUS = LONG
POINTER = ctypes.POINTER


def NtError(status):
	"""
	Converts NTSTATUS codes into WinError codes
	"""
	err = windll.ntdll.RtlNtStatusToDosError(status)
	return ctypes.WinError(err)


# https://source.winehq.org/WineAPI/RtlAdjustPrivilege.html
# BOOL WINAPI RtlAdjustPrivilege(
#   __in   ULONG     Privilege,
#   __in   BOOLEAN   Enable,
#   __in   BOOLEAN   CurrentThread,
#   __in   PBOOLEAN  Enabled,
# );
def RtlAdjustPrivilege(privilige_id, enable = True, thread_or_process = False):
	"""
	privilige_id: int
	"""
	_RtlAdjustPrivilege = windll.ntdll.RtlAdjustPrivilege
	_RtlAdjustPrivilege.argtypes = [ULONG, BOOL, BOOL, POINTER(BOOL)]
	_RtlAdjustPrivilege.restype = NTSTATUS
	
	CurrentThread = thread_or_process # enable for whole process
	Enabled = BOOL()
	
	status = _RtlAdjustPrivilege(privilige_id, enable, CurrentThread, ctypes.byref(Enabled))
	if status != STATUS_SUCCESS:
		raise Exception(NtError(status))
	
	return True


def enable_debug_privilege():
    """
    Enables the SE_DEBUG privilege for the currently running process, if the process has SE_DEBUG privilege. (You'll need to be admin most probably)
    """
    RtlAdjustPrivilege(PrivilegeValues.SE_DEBUG.value)


if __name__ == '__main__':
	enable_debug_privilege()