# Browsers
from lazagne.config.soft_import_module import soft_import
from lazagne.softwares.browsers.chromium_browsers import chromium_browsers
from lazagne.softwares.browsers.firefox_browsers import firefox_browsers

# mails
from lazagne.softwares.mails.thunderbird_mails import thunderbird_mails


def get_modules_names():
    return [
        ("lazagne.softwares.browsers.ie", "IE"),
        ("lazagne.softwares.browsers.ucbrowser", "UCBrowser"),
# Chats
        ("lazagne.softwares.chats.pidgin", "Pidgin"),
        ("lazagne.softwares.chats.psi", "PSI"),
        ("lazagne.softwares.chats.skype", "Skype"),
# Databases
        ("lazagne.softwares.databases.dbvis", "Dbvisualizer"),
        ("lazagne.softwares.databases.postgresql", "PostgreSQL"),
        ("lazagne.softwares.databases.robomongo", "Robomongo"),
        ("lazagne.softwares.databases.sqldeveloper", "SQLDeveloper"),
        ("lazagne.softwares.databases.squirrel", "Squirrel"),
# Games
        ("lazagne.softwares.games.galconfusion", "GalconFusion"),
        ("lazagne.softwares.games.kalypsomedia", "KalypsoMedia"),
        ("lazagne.softwares.games.roguestale", "RoguesTale"),
        ("lazagne.softwares.games.turba", "Turba"),
# Git
        ("lazagne.softwares.git.gitforwindows", "GitForWindows"),
# Mails
        ("lazagne.softwares.mails.outlook", "Outlook"),
# Maven
        ("lazagne.softwares.maven.mavenrepositories", "MavenRepositories"),
# Memory
        ("lazagne.softwares.memory.keepass", "Keepass"),
        ("lazagne.softwares.memory.memorydump", "MemoryDump"),
        ("lazagne.softwares.memory.onepassword", "OnePassword"),
# Multimedia
        ("lazagne.softwares.multimedia.eyecon", "EyeCON"),
# Php
        ("lazagne.softwares.php.composer", "Composer"),
# Svn
        ("lazagne.softwares.svn.tortoise", "Tortoise"),
# Sysadmin
        ("lazagne.softwares.sysadmin.apachedirectorystudio", "ApacheDirectoryStudio"),
        ("lazagne.softwares.sysadmin.coreftp", "CoreFTP"),
        ("lazagne.softwares.sysadmin.cyberduck", "Cyberduck"),
        ("lazagne.softwares.sysadmin.filezilla", "Filezilla"),
        ("lazagne.softwares.sysadmin.filezillaserver", "FilezillaServer"),
        ("lazagne.softwares.sysadmin.ftpnavigator", "FtpNavigator"),
        ("lazagne.softwares.sysadmin.opensshforwindows", "OpenSSHForWindows"),
        ("lazagne.softwares.sysadmin.openvpn", "OpenVPN"),
        ("lazagne.softwares.sysadmin.iiscentralcertp", "IISCentralCertP"),
        ("lazagne.softwares.sysadmin.keepassconfig", "KeePassConfig"),
        ("lazagne.softwares.sysadmin.iisapppool", "IISAppPool"),
        ("lazagne.softwares.sysadmin.puttycm", "Puttycm"),
        ("lazagne.softwares.sysadmin.rclone", "Rclone"),
        ("lazagne.softwares.sysadmin.rdpmanager", "RDPManager"),
        ("lazagne.softwares.sysadmin.unattended", "Unattended"),
        ("lazagne.softwares.sysadmin.vnc", "Vnc"),
        ("lazagne.softwares.sysadmin.winscp", "WinSCP"),
        ("lazagne.softwares.sysadmin.wsl", "Wsl"),
        ("lazagne.softwares.sysadmin.mRemoteNG", "mRemoteNG"),
# Wifi
        ("lazagne.softwares.wifi.wifi", "Wifi"),
# Windows
        ("lazagne.softwares.windows.autologon", "Autologon"),
        ("lazagne.softwares.windows.cachedump", "Cachedump"),
        ("lazagne.softwares.windows.credman", "Credman"),
        ("lazagne.softwares.windows.credfiles", "CredFiles"),
        ("lazagne.softwares.windows.hashdump", "Hashdump"),
        ("lazagne.softwares.windows.ppypykatz", "Pypykatz"),
        ("lazagne.softwares.windows.lsa_secrets", "LSASecrets"),
        ("lazagne.softwares.windows.vault", "Vault"),
        ("lazagne.softwares.windows.vaultfiles", "VaultFiles"),
        ("lazagne.softwares.windows.windows", "WindowsPassword")
    ]


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
        'unused': {'help': 'This modules could not be used because of broken dependence'}
    }
    return category




def get_modules():
    modules = [soft_import(package_name, module_name)() for package_name, module_name in get_modules_names()]
    return modules + chromium_browsers + firefox_browsers + thunderbird_mails
