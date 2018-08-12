# -*- coding: utf-8 -*- 
# Original code from https://github.com/joren485/PyWinPrivEsc/blob/master/RunAsSystem.py

import sys
import psutil
from lazagne.config.write_output import print_debug
from lazagne.config.winstructure import *

import os


def get_token_sid(hToken):
    """
    Retrieve SID from Token
    """
    dwSize = DWORD(0)
    pStringSid = LPSTR()
    TokenUser = 1

    if GetTokenInformation(hToken, TokenUser, byref(TOKEN_USER()), 0, byref(dwSize)) == 0:
        address = LocalAlloc(0x0040, dwSize)
        if address:
            GetTokenInformation(hToken, TokenUser, address, dwSize, byref(dwSize))
            pToken_User = cast(address, POINTER(TOKEN_USER))
            if pToken_User.contents.User.Sid:
                ConvertSidToStringSidA(pToken_User.contents.User.Sid, byref(pStringSid))
                if pStringSid:
                    sid = pStringSid.value
                    LocalFree(address)
                    return sid
    return False


def enable_privilege(privilegeStr, hToken=None):
    """
    Enable Privilege on token, if no token is given the function gets the token of the current process.
    """
    if hToken == None:
        hToken = HANDLE(INVALID_HANDLE_VALUE)
        if not hToken:
            return False

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, os.getpid())
        if not hProcess:
            return False

        OpenProcessToken(hProcess, (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), byref(hToken))
        e = GetLastError()
        if e != 0:
            return False
        CloseHandle(hProcess)

    privilege_id = LUID()
    LookupPrivilegeValueA(None, privilegeStr, byref(privilege_id))
    e = GetLastError()
    if e != 0:
        return False

    SE_PRIVILEGE_ENABLED = 0x00000002
    laa = LUID_AND_ATTRIBUTES(privilege_id, SE_PRIVILEGE_ENABLED)
    tp = TOKEN_PRIVILEGES(1, laa)

    AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), None, None)
    e = GetLastError()
    if e != 0:
        return False
    return True


def get_debug_privilege():
    """
    Enable Debug privilege on token
    """
    if enable_privilege("SeDebugPrivilege"):
        return True
    else:
        return False


def list_sids():
    """
    List all SID by process
    """
    sids = []

    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'username', 'name'])
        except psutil.NoSuchProcess:
            continue
        except WindowsError as e:
            if e.winerror == 1722:  # WindowsError: [Error 1722] The RPC server is unavailable
                continue

        if pinfo['pid'] <= 4:
            continue
        if pinfo['username'] is None:
            continue
        try:
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, int(pinfo['pid']))
            if not hProcess:
                continue

            hToken = HANDLE(INVALID_HANDLE_VALUE)
            if not hToken:
                continue

            OpenProcessToken(hProcess, tokenprivs, byref(hToken))
            if not hToken:
                continue

            token_sid = get_token_sid(hToken)
            if not token_sid:
                continue
            sids.append((pinfo['pid'], pinfo['name'], token_sid, pinfo['username'].decode(sys.getfilesystemencoding())))

            CloseHandle(hToken)
            CloseHandle(hProcess)
        except Exception as e:
            print_debug('ERROR', u'{error}'.format(error=e))

    return list(sids)


def get_sid_token(token_sid):
    if token_sid == "S-1-5-18":
        sids = list_sids()
        for sid in sids:
            if "winlogon" in sid[1].lower():
                try:
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, sid[0])
                    if hProcess:
                        hToken = HANDLE(INVALID_HANDLE_VALUE)
                        if hToken:
                            OpenProcessToken(hProcess, tokenprivs, byref(hToken))
                            if hToken:
                                print_debug('INFO', u'Using PID: ' + str(sid[0]))
                                CloseHandle(hProcess)
                                return hToken

                    # CloseHandle(hToken)
                    CloseHandle(hProcess)
                except Exception as e:
                    print_debug('ERROR', u'{error}'.format(error=e))
                    break
        return False

    pids = [int(x) for x in psutil.pids() if int(x) > 4]
    for pid in pids:
        try:
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, False, int(pid))
            if hProcess:
                hToken = HANDLE(INVALID_HANDLE_VALUE)
                if hToken:
                    OpenProcessToken(hProcess, tokenprivs, byref(hToken))
                    if hToken:
                        if get_token_sid(hToken) == token_sid:
                            print
                            print_debug('INFO', u'Using PID: ' + str(pid))
                            CloseHandle(hProcess)
                            return hToken
                    CloseHandle(hToken)
            CloseHandle(hProcess)
        except Exception as e:
            print_debug('ERROR', u'{error}'.format(error=e))

    return False


def impersonate_sid(sid, close=True):
    """
    Try to impersonate an SID
    """
    hToken = get_sid_token(sid)
    if hToken:
        hTokendupe = impersonate_token(hToken)
        if hTokendupe:
            if close:
                CloseHandle(hTokendupe)
            return hTokendupe
    return False


global_ref = None


def impersonate_sid_long_handle(*args, **kwargs):
    """
    Try to impersonate an SID
    """
    global global_ref
    hTokendupe = impersonate_sid(*args, **kwargs)
    if not hTokendupe:
        return False

    if global_ref:
        CloseHandle(global_ref)

    global_ref = hTokendupe
    return addressof(hTokendupe)


def impersonate_token(hToken):
    """
    Impersonate token - Need admin privilege
    """
    if get_debug_privilege():
        hTokendupe = HANDLE(INVALID_HANDLE_VALUE)
        if hTokendupe:
            SecurityImpersonation = 2
            TokenPrimary = 1
            if DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, byref(hTokendupe)):
                CloseHandle(hToken)
                if ImpersonateLoggedOnUser(hTokendupe):
                    return hTokendupe
    return False


def rev2self():
    """
    Back to previous token priv
    """
    global global_ref
    RevertToSelf()
    try:
        if global_ref:
            CloseHandle(global_ref)
    except Exception:
        pass
    global_ref = None
