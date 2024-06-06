#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lazagne.config.soft_import_module import soft_import
# browsers
from lazagne.softwares.browsers.firefox_browsers import firefox_browsers
from lazagne.softwares.browsers.chromium_browsers import chromium_browsers

# mails
from lazagne.softwares.mails.thunderbird_mails import thunderbird_mails

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


def get_modules_names():
    return [
        ("lazagne.softwares.mails.clawsmail", "ClawsMail"),
        ("lazagne.softwares.databases.dbvis", "DbVisualizer"),
        ("lazagne.softwares.sysadmin.env_variable", "Env_variable"),
        ("lazagne.softwares.sysadmin.apachedirectorystudio", "ApacheDirectoryStudio"),
        ("lazagne.softwares.sysadmin.filezilla", "Filezilla"),
        ("lazagne.softwares.sysadmin.fstab", "Fstab"),
        ("lazagne.softwares.browsers.opera", "Opera"),
        ("lazagne.softwares.chats.pidgin", "Pidgin"),
        ("lazagne.softwares.chats.psi", "PSI"),
        ("lazagne.softwares.sysadmin.shadow", "Shadow"),
        ("lazagne.softwares.sysadmin.aws", "Aws"),
        ("lazagne.softwares.sysadmin.docker", "Docker"),
        ("lazagne.softwares.sysadmin.rclone", "Rclone"),
        ("lazagne.softwares.sysadmin.ssh", "Ssh"),
        ("lazagne.softwares.sysadmin.cli", "Cli"),
        ("lazagne.softwares.sysadmin.gftp", "gFTP"),
        ("lazagne.softwares.sysadmin.keepassconfig", "KeePassConfig"),
        ("lazagne.softwares.sysadmin.grub", "Grub"),
        ("lazagne.softwares.databases.sqldeveloper", "SQLDeveloper"),
        ("lazagne.softwares.databases.squirrel", "Squirrel"),
        ("lazagne.softwares.wifi.wifi", "Wifi"),
        ("lazagne.softwares.wifi.wpa_supplicant", "Wpa_supplicant"),
        ("lazagne.softwares.wallet.kde", "Kde"),
        ("lazagne.softwares.wallet.libsecret", "Libsecret"),
        ("lazagne.softwares.memory.mimipy", "Mimipy"),
        ("lazagne.softwares.git.gitforlinux", "GitForLinux")
    ]

    # very long to execute
    # try:
    # 	module_names.append(MemoryDump())
    # except:
    # 	pass


def get_modules():
    modules = [soft_import(package_name, module_name)() for package_name, module_name in get_modules_names()]
    return modules + chromium_browsers + firefox_browsers + thunderbird_mails
