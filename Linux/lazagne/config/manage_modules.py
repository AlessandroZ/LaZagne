#!/usr/bin/env python
# -*- coding: utf-8 -*- 
# keyring
from lazagne.softwares.wallet.kde import Kde
from lazagne.softwares.wallet.libsecret import Libsecret
# browsers
from lazagne.softwares.browsers.mozilla import firefox_browsers
from lazagne.softwares.browsers.opera import Opera
from lazagne.softwares.browsers.chrome import Chrome
# sysadmin
from lazagne.softwares.sysadmin.apachedirectorystudio import ApacheDirectoryStudio
from lazagne.softwares.sysadmin.filezilla import Filezilla
from lazagne.softwares.sysadmin.fstab import Fstab
from lazagne.softwares.sysadmin.env_variable import Env_variable
from lazagne.softwares.sysadmin.shadow import Shadow
from lazagne.softwares.sysadmin.aws import Aws
from lazagne.softwares.sysadmin.ssh import Ssh
from lazagne.softwares.sysadmin.docker import Docker
from lazagne.softwares.sysadmin.cli import Cli
from lazagne.softwares.sysadmin.gftp import gFTP
from lazagne.softwares.sysadmin.keepassconfig import KeePassConfig
from lazagne.softwares.sysadmin.grub import Grub
# chats
from lazagne.softwares.chats.pidgin import Pidgin
from lazagne.softwares.chats.psi import PSI
# mails
from lazagne.softwares.mails.clawsmail import ClawsMail
from lazagne.softwares.mails.thunderbird import Thunderbird
# wifi
from lazagne.softwares.wifi.wifi import Wifi
from lazagne.softwares.wifi.wpa_supplicant import Wpa_supplicant
# databases
from lazagne.softwares.databases.squirrel import Squirrel
from lazagne.softwares.databases.dbvis import DbVisualizer
from lazagne.softwares.databases.sqldeveloper import SQLDeveloper

# memory
from lazagne.softwares.memory.mimipy import Mimipy

# git
from lazagne.softwares.git.gitforlinux import GitForLinux
try:
    from lazagne.softwares.memory.memorydump import MemoryDump
except ImportError:
    pass


def get_categories():
    category = {
        'chats': {'help': 'Chat clients supported'},
        'sysadmin': {'help': 'SCP/SSH/FTP/FTPS clients supported'},
        'databases': {'help': 'SQL clients supported'},
        'mails': {'help': 'Email clients supported'},
        'memory': {'help': 'Retrieve passwords from memory'},
        'wifi': {'help': 'Wifi'},
        'browsers': {'help': 'Web browsers supported'},
        'wallet': {'help': 'Windows credentials (credential manager, etc.)'},
        'git': {'help': 'GIT clients supported'}
    }
    return category


def get_modules():
    module_names = [
        ClawsMail(),
        Thunderbird(),
        DbVisualizer(),
        Env_variable(),
        ApacheDirectoryStudio(),
        Filezilla(),
        Fstab(),
        # Mozilla(),
        Opera(),
        Chrome(),
        Pidgin(),
        PSI(),
        Shadow(),
        Aws(),
        Docker(),
        Ssh(),
        Cli(),
        gFTP(),
        KeePassConfig(),
        Grub(),
        SQLDeveloper(),
        Squirrel(),
        Wifi(),
        Wpa_supplicant(),
        Kde(),
        Libsecret(), 
        Mimipy(),
        GitForLinux()
    ]

    # very long to execute
    # try:
    # 	module_names.append(MemoryDump())
    # except:
    # 	pass

    return module_names + firefox_browsers
