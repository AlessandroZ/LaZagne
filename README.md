# **The LaZagne Project !!!**

## Description

The **LaZagne project** is an open source application used to **retrieve lots of passwords** stored on a local computer.
Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software.

<p align="center"><img src="https://user-images.githubusercontent.com/10668373/43320585-3e34c124-91a9-11e8-9ebc-d8eabafd8ac5.png" alt="The LaZagne project"></p>

This project has been added to [pupy](https://github.com/n1nj4sec/pupy/) as a post-exploitation module. Python code will be interpreted in memory without touching the disk and it works on Windows and Linux host. The last Linux release is not up to date so I recommend using pupy to use it.

## Standalones

Standalones are now available here: <https://github.com/AlessandroZ/LaZagne/releases/>

## Installation

Requirements are available here: <https://github.com/AlessandroZ/LaZagne/wiki/Requirements>

    pip install -r requirement.txt

## Usage

-   Retrieve version


    laZagne.exe --version

-   Launch all modules


    laZagne.exe all

-   Launch only a specific module


    laZagne.exe browsers

-   Launch only a specific software script


    laZagne.exe browsers -firefox

-   Write all passwords found into a file (-oN for Normal txt, -oJ for Json, -oA for All).
    Note: If you have problems to parse JSON results written as a multi-line strings, check [this](https://github.com/AlessandroZ/LaZagne/issues/226).


    laZagne.exe all -oN
    laZagne.exe all -oA -output C:\Users\test\Desktop

-   Get help


    laZagne.exe -h
    laZagne.exe browsers -h

-   Change verbosity mode (2 different levels)


    laZagne.exe all -vv

-   Quiet mode (nothing will be printed on the standard output)


    laZagne.exe all -quiet -oA

-   To decrypt domain credentials, it could be done specifying the user windows password. Otherwise it will try all passwords already found as windows passwords.


    laZagne.exe all -password ZapataVive

**Note: For wifi passwords \\ Windows Secrets, launch it with administrator privileges (UAC Authentication / sudo)**

## Mac OS

**Note: In Mac OS System, without the user password it is very difficult to retrieve passwords stored on the computer.**
So, I recommend using one of these options

-   If you know the user password, add it in the command line


    laZagne all --password SuperSecurePassword

-   You could use the interactive mode that will prompt a dialog box to the user until the password will be correct


    laZagne all -i

## Supported software

|                                      | Windows                                                                                                                                        | Linux                                                                            | Mac                 |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------------------- |
| Browser                              | Chrome, firefox, IE, Opera                                                                                                                     | Firefox, Opera                                                                   | Firefox, Chrome     |
| Chats                                | Jitsy, Pigdin, Skype                                                                                                                           | Jitsy, Pigdin                                                                    |                     |
| Databases                            | DBVisualizer, Postgresql, Robomongo, Squirrel, SQLdevelopper                                                                                   | DBVisualizer, Squirrel, SQLdevelopper                                            |                     |
| Games                                | GalconFusion, Kalypsomedia, RogueTale, Turba                                                                                                   |                                                                                  |                     |
| Git                                  | Git for Windows                                                                                                                                |                                                                                  |                     |
| Mails                                | Outlook, Thunderbird                                                                                                                           | Clawsmail, Thunderbird                                                           |                     |
| Dumps from memory                    | Keepass, Wdigest (mimikatz method)                                                                                                             | system password                                                                  |                     |
| SVN                                  | Tortoise                                                                                                                                       |                                                                                  |                     |
| Sysadmin                             | Apache Directory studio, CoreFTP, CyberDuck, fileZilla, FTPNavigator, OpenSSH, OpenVPN, PuttyCMRDPManager, WinSCP, Windows Subsystem for Linux | AWS,  Docker, Environnement variable, FileZilla, History files, SSH private keys |                     |
| Wifi                                 | Wireless Network                                                                                                                               | Network Manager                                                                  | \* CF Keychains     |
| Internal mechanism passwords storage | .NET Passport, Generic Network Hashdump (LM/NT), LSA secret                                                                                    | GNOME Keyring, Kwallet,hashdump                                                  | Keychains, hashdump |

(\*) used by many tools to store passwords: Chrome, Owncloud, Evolution, KMail, etc.

## For developers

Please refer to the wiki before opening an issue to understand how to compile the project or to develop a new module.
<https://github.com/AlessandroZ/LaZagne/wiki>

## Donation

If you want to support my work doing a donation, I will appreciate a lot:

-   Via BTC: 16zJ9wTXU4f1qfMLiWvdY3woUHtEBxyriu
-   Via Paypal: <https://www.paypal.me/lazagneproject>

## Special thanks

-   Harmjoy for [KeeThief](https://github.com/HarmJ0y/KeeThief/)
-   n1nj4sec for his [mimipy](https://github.com/n1nj4sec/mimipy) module
-   Benjamin DELPY for [mimikatz](https://github.com/gentilkiwi/mimikatz), which helps me to understand some Windows API.
-   @skelsec for [Pypykatz](https://github.com/skelsec/pypykatz)
-   Moyix for [Creddump](https://github.com/moyix/creddump)
-   N0fat for [Chainbreaker](https://github.com/n0fate/chainbreaker/)
-   Richard Moore for the [AES module](https://github.com/ricmoo/pyaes)
-   Todd Whiteman for the [DES module](https://github.com/toddw-as/pyDes)
-   mitya57 for [secretstorage](https://github.com/mitya57/secretstorage)
-   All [contributors](https://github.com/AlessandroZ/LaZagne/graphs/contributors) who help me on this project

* * *

\| **Alessandro ZANNI**    \|
\| ------------- \|
\| **zanni.alessandro@gmail.com**  \|
