
__The LaZagne Project !!!__
==

Description
----
The __LaZagne project__ is an open source application used to __retrieve lots of passwords__ stored on a local computer. 
Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software. 
At this moment, it supports 22 Programs on Microsoft Windows and 12 on a Linux/Unix-Like OS.

<p align="center"><img src="./pictures/lazagne.png" alt="The LaZagne project"></p>

Standalones
----
Standalones are now available here: https://github.com/AlessandroZ/LaZagne/releases/

Usage
----
* Retrieve version
	* cmd: laZagne.exe --version

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

* Use a file for dictionary attacks (used only when it's necessary: mozilla masterpassword, system hahes, etc.). The file has to be a wordlist in cleartext (no rainbow), it has not been optmized to be fast but could useful for basic passwords. 
	* cmd: laZagne.exe all -path file.txt

* Change verbosity mode (2 different levels)
	* cmd: laZagne.exe all -vv

__Note: For wifi passwords \ Windows Secrets, launch it with administrator privileges (UAC Authentication / sudo)__

Supported software
----

<p align="center"><img src="./pictures/softwares.png" alt="The LaZagne project"></p>

(*) used by many tools to store passwords: Chrome, Owncloud, Evolution, KMail, etc.

IE Browser history
----
Internet Explorer passwords (from IE7 and before Windows 8) can only be decrypted using the URL of the website. This one is used as an argument of the Win32CryptUnprotectData api. Thus, using the browsing history of ie will permit to decrypt many passwords. 
To do that, I used a dll written in C code (the code is in the "browser_history_dll" directory) and it is directly embedded to the Python code as a Base64 string (c.f. ie.py). Once launched, the dll is written on the disk, a wrapper is used to call dll functions and then the dll file is removed from the disk.

Windows hashes
----
To dump windows hashes and LSA Secrets, the impacket library has been used: https://github.com/CoreSecurity/impacket

Build your own password recovery script
----
It's possible to write your own script for the software of your choice. Building your own module has become extremely easy. 

To do that, some code standards are to be met: 
* Create a class using the name of the software containing 2 importants functions:
	* init: used to define all arguments used to launch the class. 
	* run:  will be the main function

* Add on the config.manageModules.py file your class name and your import

* The output containing all passwords has to be send to the "print_output" function - ex: print_output(software_name, password_list)
	* password_list has to be an array of dictionnaries. 

* Optional: you could use the function "print_debug" to print your output 
	* ex: print_debug("ERROR", "Failed to load ...")

* Use an existing script to understand what I have said :)

If you want to improve this tool, you can send me your script and it will be added to this project (authors will be, of course, credited on each script ;)).

Requirements
----
To compile the source code, some external libraries are required.

* For Windows
	* Python 2.7
	* Colorama (for the Console colors): https://pypi.python.org/pypi/colorama
	* Python for Windows Extensions: http://sourceforge.net/projects/pywin32/
	* PyCrypto: pip install pycrypto
	* Impacket (for Windows hashes + LSA Secrets): https://github.com/CoreSecurity/impacket
	* Pyasn1 (for ASN1 decoding): https://pypi.python.org/pypi/pyasn1/

* For Linux	
	* Python 2.7
	* Argparse
	* PyCrypto: https://www.dlitz.net/software/pycrypto/
	* Dbus (Pidgin)
	* Python-kde4 (Kwallet)
	* Pyasn1 (for ASN1 decoding): https://pypi.python.org/pypi/pyasn1/

----
| __Alessandro ZANNI__    |
| ------------- |
| __alessandro.zanni@bt.com__    |
| __zanni.alessandro@gmail.com__  |


 

