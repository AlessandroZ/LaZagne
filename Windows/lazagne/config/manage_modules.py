# Browsers
from lazagne.softwares.browsers.chromium_based import chromium_browsers
from lazagne.softwares.browsers.ie import IE
from lazagne.softwares.browsers.mozilla import firefox_browsers
from lazagne.softwares.browsers.ucbrowser import UCBrowser
# Chats
from lazagne.softwares.chats.pidgin import Pidgin
from lazagne.softwares.chats.psi import PSI
from lazagne.softwares.chats.skype import Skype
# Databases
from lazagne.softwares.databases.dbvis import Dbvisualizer
from lazagne.softwares.databases.postgresql import PostgreSQL
from lazagne.softwares.databases.robomongo import Robomongo
from lazagne.softwares.databases.sqldeveloper import SQLDeveloper
from lazagne.softwares.databases.squirrel import Squirrel
# Games
from lazagne.softwares.games.galconfusion import GalconFusion
from lazagne.softwares.games.kalypsomedia import KalypsoMedia
from lazagne.softwares.games.roguestale import RoguesTale
from lazagne.softwares.games.turba import Turba
# Git
from lazagne.softwares.git.gitforwindows import GitForWindows
# Mails
from lazagne.softwares.mails.outlook import Outlook
from lazagne.softwares.mails.thunderbird import Thunderbird
# Maven
from lazagne.softwares.maven.mavenrepositories import MavenRepositories
# Memory
from lazagne.softwares.memory.keepass import Keepass
from lazagne.softwares.memory.memorydump import MemoryDump
# Multimedia
from lazagne.softwares.multimedia.eyecon import EyeCON
# Php
from lazagne.softwares.php.composer import Composer
# Svn
from lazagne.softwares.svn.tortoise import Tortoise
# Sysadmin
from lazagne.softwares.sysadmin.apachedirectorystudio import ApacheDirectoryStudio
from lazagne.softwares.sysadmin.coreftp import CoreFTP
from lazagne.softwares.sysadmin.cyberduck import Cyberduck
from lazagne.softwares.sysadmin.filezilla import Filezilla
from lazagne.softwares.sysadmin.filezillaserver import FilezillaServer
from lazagne.softwares.sysadmin.ftpnavigator import FtpNavigator
from lazagne.softwares.sysadmin.opensshforwindows import OpenSSHForWindows
from lazagne.softwares.sysadmin.openvpn import OpenVPN
from lazagne.softwares.sysadmin.iiscentralcertp import IISCentralCertP
from lazagne.softwares.sysadmin.keepassconfig import KeePassConfig
from lazagne.softwares.sysadmin.iisapppool import IISAppPool
from lazagne.softwares.sysadmin.puttycm import Puttycm
from lazagne.softwares.sysadmin.rdpmanager import RDPManager
from lazagne.softwares.sysadmin.unattended import Unattended
from lazagne.softwares.sysadmin.vnc import Vnc
from lazagne.softwares.sysadmin.winscp import WinSCP
from lazagne.softwares.sysadmin.wsl import Wsl
# Wifi
from lazagne.softwares.wifi.wifi import Wifi
# Windows
from lazagne.softwares.windows.autologon import Autologon
from lazagne.softwares.windows.cachedump import Cachedump
from lazagne.softwares.windows.credman import Credman
from lazagne.softwares.windows.credfiles import CredFiles
from lazagne.softwares.windows.hashdump import Hashdump
from lazagne.softwares.windows.ppypykatz import Pypykatz
from lazagne.softwares.windows.lsa_secrets import LSASecrets
from lazagne.softwares.windows.vault import Vault
from lazagne.softwares.windows.vaultfiles import VaultFiles
from lazagne.softwares.windows.windows import WindowsPassword


def get_categories():
    category = {
        'browsers': {'help': 'Web browsers supported'},
        'chats': {'help': 'Chat clients supported'},
        'databases': {'help': 'SQL/NoSQL clients supported'},
        'games': {'help': 'Games etc.'},
        'git': {'help': 'GIT clients supported'},
        'mails': {'help': 'Email clients supported'},
        'maven': {'help': 'Maven java build tool'},
        'memory': {'help': 'Retrieve passwords from memory'},
        'multimedia': {'help': 'Multimedia applications, etc'},
        'php': {'help': 'PHP build tool'},
        'svn': {'help': 'SVN clients supported'},
        'sysadmin': {'help': 'SCP/SSH/FTP/FTPS clients supported'},
        'windows': {'help': 'Windows credentials (credential manager, etc.)'},
        'wifi': {'help': 'Wifi'},
    }
    return category


def get_modules():
    module_names = [

        # Browser
        IE(),
        UCBrowser(),

        # Chats
        Pidgin(),
        Skype(),
        PSI(),

        # Databases
        Dbvisualizer(),
        Squirrel(),
        SQLDeveloper(),
        Robomongo(),
        PostgreSQL(),

        # games
        KalypsoMedia(),
        GalconFusion(),
        RoguesTale(),
        Turba(),

        # Git
        GitForWindows(),

        # Mails
        Outlook(),
        Thunderbird(),

        # Maven
        MavenRepositories(),

        # Memory
        MemoryDump(),  # retrieve browsers and keepass passwords
        Keepass(),  # should be launched after memory dump

        # Multimedia
        EyeCON(),

        # Php
        Composer(),

        # SVN
        Tortoise(),

        # Sysadmin
        ApacheDirectoryStudio(),
        CoreFTP(),
        Cyberduck(),
        Filezilla(),
        FilezillaServer(),
        FtpNavigator(),
        KeePassConfig(),
        Puttycm(),
        OpenSSHForWindows(),
        OpenVPN(),
        IISCentralCertP(),
        IISAppPool(),
        RDPManager(),
        Unattended(),
        WinSCP(),
        Vnc(),
        Wsl(),

        # Wifi
        Wifi(),

        # Windows
        Autologon(),
        Pypykatz(),
        Cachedump(),
        Credman(),
        Hashdump(),
        LSASecrets(),
        CredFiles(),
        Vault(),
        VaultFiles(),
        WindowsPassword(),
    ]
    return module_names + chromium_browsers + firefox_browsers
