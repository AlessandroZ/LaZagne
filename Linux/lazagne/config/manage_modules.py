#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lazagne.config.soft_import_module import soft_import
# browsers
from lazagne.softwares.browsers.firefox_browsers import firefox_browsers
from lazagne.softwares.browsers.chromium_browsers import chromium_browsers

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
        'git': {'help': 'GIT clients supported'},
        'unused': {'help': 'This modules could not be used because of broken dependence'}
    }
    return category


def get_modules():
    module_names = [
        soft_import("lazagne.softwares.mails.clawsmail", "ClawsMail")(),
        soft_import("lazagne.softwares.mails.thunderbird", "Thunderbird")(),
        soft_import("lazagne.softwares.databases.dbvis", "DbVisualizer")(),
        soft_import("lazagne.softwares.sysadmin.env_variable", "Env_variable")(),
        soft_import("lazagne.softwares.sysadmin.apachedirectorystudio", "ApacheDirectoryStudio")(),
        soft_import("lazagne.softwares.sysadmin.filezilla", "Filezilla")(),
        soft_import("lazagne.softwares.sysadmin.fstab", "Fstab")(),
        soft_import("lazagne.softwares.browsers.opera", "Opera")(),
        soft_import("lazagne.softwares.chats.pidgin", "Pidgin")(),
        soft_import("lazagne.softwares.chats.psi", "PSI")(),
        soft_import("lazagne.softwares.sysadmin.shadow", "Shadow")(),
        soft_import("lazagne.softwares.sysadmin.aws", "Aws")(),
        soft_import("lazagne.softwares.sysadmin.docker", "Docker")(),
        soft_import("lazagne.softwares.sysadmin.ssh", "Ssh")(),
        soft_import("lazagne.softwares.sysadmin.cli", "Cli")(),
        soft_import("lazagne.softwares.sysadmin.gftp", "gFTP")(),
        soft_import("lazagne.softwares.sysadmin.keepassconfig", "KeePassConfig")(),
        soft_import("lazagne.softwares.sysadmin.grub", "Grub")(),
        soft_import("lazagne.softwares.databases.sqldeveloper", "SQLDeveloper")(),
        soft_import("lazagne.softwares.databases.squirrel", "Squirrel")(),
        soft_import("lazagne.softwares.wifi.wifi", "Wifi")(),
        soft_import("lazagne.softwares.wifi.wpa_supplicant", "Wpa_supplicant")(),
        soft_import("lazagne.softwares.wallet.kde", "Kde")(),
        soft_import("lazagne.softwares.wallet.libsecret", "Libsecret")(),
        soft_import("lazagne.softwares.memory.mimipy", "Mimipy")(),
        soft_import("lazagne.softwares.git.gitforlinux", "GitForLinux")()
    ]

    # very long to execute
    # try:
    # 	module_names.append(MemoryDump())
    # except:
    # 	pass

    return module_names + chromium_browsers + firefox_browsers
