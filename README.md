
__The LaZagne Project !!!__
==

Description
----
The __LaZagne project__ is an open source application used to __retrieve lots of passwords__ stored on a local computer. 
Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software. 
At this moment, it supports 22 Programs on Microsoft Windows and 12 on a Linux/Unix-Like OS.

<p align="center"><img src="./pictures/lazagne.png" alt="The LaZagne project"></p>

Usage
----
* Launch all modules
	* cmd: laZagne.exe all

* Launch only a specific module
	* cmd: laZagne.exe <module_name>
	* example: laZagne.exe browsers
	* help: laZagne.exe -h

* Launch only a specific software script
	* cmd: laZagne.exe <module_name> <software>
	* example: laZagne.exe browsers -f
	* help: laZagne.exe browsers -h

* Write all passwords found into a file (-w options)
	* cmd: laZagne.exe all -w

__Note: For wifi passwords, launch it with administrator privileges (UAC Authentication / sudo)__

Supported software
----

* __Windows__ (tested on Windows XP, 7 and 8 - 32 and 64 bits)
	* Browsers
		* Firefox
		* Chrome
		* Opera
		* Explorer

	* chats
		* Skype
		* Pidgin
		* Jitsi

	* mails
		* Thunderbird
		* Outlook

	* adminsys
		* Filezilla
		* PuttyCM
		* WinSCP
		* Cyberduck
		* CoreFTP
		* FTPNavigator

	* database
		* SQLdeveloper
		* Squirrel
		* DBvisualizer

	* svn
		* Tortoise

	* wifi
		* Wireless Network Password (Windows Feature)

	* windows credentials
		* Domain visible network (.NET Passport)
		* Generic network credentials

* __Linux__
	* browsers
		* Firefox
		* Opera

	* chats
		* Pidgin
		* Jitsi

	* mails
		* Thunderbird

	* adminsys
		* Filezilla
		* Environment variables

	* database
		* SQLdeveloper
		* Squirrel
		* DBvisualizer

	* wifi
		* Network Manager

	* wallet
		* GNOME Keyring


IE Browser history
----
Internet Explorer passwords (from IE7 and before Windows 8) can only be decrypted using the URL of the website. This one is used as an argument of the Win32CryptUnprotectData api. So to decrypt it, it is only necessary to retreive the browsing history of ie. 
To do that, I used C code. So I used a dll (the code is in the "browser_history_dll" directory) and it is directly embedded to the Python code as a Base64 string (c.f. ie.py). Once launched, the dll is written to the disk, a wrapper is used to call dll functions and then the dll file is removed from the disk.

Build your own password recovery script
----
It's possible to write your own script for the software of your choice. 

To do that, some code standards are to be met: 
* Create a class using the name of the software
* This class has to have a function called "retrieve_password" (it will be the main function)
* The output containing all passwords has to be send to the "print_output" function - ex: print_output(<software_name>, password_list)
	* password_list has to be an array of dictionnaries. 
* Optional: you could use the function "print_debug" to print your output 
	* ex: print_debug("ERROR", "Failed to load ...")
* Use an existing script to understand what I have said :)

If you want to improve this tool, you can send me your script and it will be added to this project (authors will be, of course, credited on each script ;)).

Requirements
----
To compile the source code, some external libraries are required.

* For Windows
	* WConio (for the Console colors)
		* http://newcenturycomputers.net/projects/wconio.html
		* http://newcenturycomputers.net/projects/download.cgi/WConio-1.5.win32-py2.7.exe

	* Python for Windows Extensions
		* http://sourceforge.net/projects/pywin32/

* For Linux
	* None for Ubuntu 14.04
	* Other distributions
		* crypto
		* dbus

----
| __Alessandro ZANNI__    |
| ------------- |
| __alessandro.zanni@bt.com__    |
| __zanni.alessandro@gmail.com__  |


 

