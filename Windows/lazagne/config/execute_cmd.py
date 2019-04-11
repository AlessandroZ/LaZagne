# -*- coding: utf-8 -*-
# !/usr/bin/python
import base64
import os
import subprocess
import re

from lazagne.config.write_output import print_debug
from lazagne.config.constant import constant

try: 
    import _subprocess as sub
    STARTF_USESHOWWINDOW = sub.STARTF_USESHOWWINDOW  # Not work on Python 3
    SW_HIDE = sub.SW_HIDE
except ImportError:
    STARTF_USESHOWWINDOW = subprocess.STARTF_USESHOWWINDOW
    SW_HIDE = subprocess.SW_HIDE


def powershell_execute(script, func):
    """
    Execute a powershell script
    """
    output = ""
    try:
        script = re.sub("Write-Verbose ", "Write-Output ", script, flags=re.I)
        script = re.sub("Write-Error ", "Write-Output ", script, flags=re.I)
        script = re.sub("Write-Warning ", "Write-Output ", script, flags=re.I)

        full_args = ["powershell.exe", "-NoProfile", "-NoLogo", "-C", "-"]

        info = subprocess.STARTUPINFO()
        info.dwFlags = STARTF_USESHOWWINDOW
        info.wShowWindow = SW_HIDE

        p = subprocess.Popen(full_args, startupinfo=info, stdin=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdout=subprocess.PIPE, universal_newlines=True, shell=True)
        p.stdin.write("$base64=\"\"" + "\n")

        n = 25000
        b64_script = base64.b64encode(script)
        tab = [b64_script[i:i + n] for i in range(0, len(b64_script), n)]
        for t in tab:
            p.stdin.write("$base64+=\"%s\"\n" % t)
            p.stdin.flush()

        p.stdin.write("$d=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))\n")
        p.stdin.write("Invoke-Expression $d\n")

        p.stdin.write("\n$a=Invoke-Expression \"%s\" | Out-String\n" % func)
        p.stdin.write("$b=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(\"$a\"))\n")
        p.stdin.write("Write-Host \"[BEGIN]\"\n")
        p.stdin.write("Write-Host $b\n")

        # begin flag used to remove possible bullshit output print before the func is launched
        if '[BEGIN]' in p.stdout.readline():
            # Get the result in base64
            for i in p.stdout.readline():
                output += i
            output = base64.b64decode(output)
    except Exception:
        pass

    return output


def save_hives():
    """
    Save SAM Hives
    """
    for h in constant.hives:
        if not os.path.exists(constant.hives[h]):
            try:
                cmdline = 'reg.exe save hklm\%s %s' % (h, constant.hives[h])
                command = ['cmd.exe', '/c', cmdline]
                info = subprocess.STARTUPINFO()
                info.dwFlags = STARTF_USESHOWWINDOW
                info.wShowWindow = SW_HIDE
                p = subprocess.Popen(command, startupinfo=info, stdin=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     stdout=subprocess.PIPE, universal_newlines=True)
                results, _ = p.communicate()
            except Exception as e:
                print_debug('ERROR', u'Failed to save system hives: {error}'.format(error=e))
                return False
    return True


def delete_hives():
    """
    Delete SAM Hives
    """
    # Try to remove all temporary files
    for h in constant.hives:
        if os.path.exists(constant.hives[h]):
            try:
                os.remove(constant.hives[h])
                print_debug('DEBUG', u'Temp {hive} removed: {filename}'.format(hive=h, filename=constant.hives[h]))
            except Exception:
                print_debug('DEBUG', u'Temp {hive} failed to removed: {filename}'.format(hive=h, filename=constant.hives[h]))

