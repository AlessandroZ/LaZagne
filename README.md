
__The LaZagne Project !!!__
==

Description
----
The __LaZagne project__ is an open source application used to __retrieve lots of passwords__ stored on a local computer. 
Each software stores its passwords using different techniques (plaintext, APIs, custom algorithms, databases, etc.). This tool has been developed for the purpose of finding these passwords for the most commonly-used software. 

<p align="center"><img src="./pictures/lazagne.png" alt="The LaZagne project"></p>

Standalones
----
Standalones are now available here: https://github.com/AlessandroZ/LaZagne/releases/

Usage
----
* Retrieve version
```
laZagne.exe --version
```

* Launch all modules
```
laZagne.exe all
```

* Launch only a specific module
```
laZagne.exe browsers
```

* Launch only a specific software script
```
laZagne.exe browsers -f (for firefox)
```

* Write all passwords found into a file (-oN for Normal txt, -oJ for Json, -oA for All)
```
laZagne.exe all -oN
```

* Get help
```
laZagne.exe -h
laZagne.exe browsers -h
```

* Use a file for dictionary attacks (used only when it's necessary: mozilla masterpassword, system hahes, etc.). The file has to be a wordlist in cleartext (no rainbow), it has not been optmized to be fast but could useful for basic passwords.
```
laZagne.exe all -path file.txt
```

* Change verbosity mode (2 different levels)
```
laZagne.exe all -vv
```

__Note: For wifi passwords \ Windows Secrets, launch it with administrator privileges (UAC Authentication / sudo)__

Supported software
----

<p align="center"><img src="./pictures/softwares.png" alt="The LaZagne project"></p>

(*) used by many tools to store passwords: Chrome, Owncloud, Evolution, KMail, etc.

User impersonnation
----
When laZagne is launched with admin privileges (UAC bypassed) or System, it manages to retrieve passwords from other users. It uses two ways to do that: 

* If a process from another user is launched (using runas or if many users are connected to the same host), it manages to steal a process token to launch laZagne with its privileges (this is the best way). It could retrieve passwords stored encrypted with the Windows API. 
	
* If no process has been launched but other user exists (visible on the file system in C:\Users\...), it browses the file system in order to retrieve passwords from these users. However, it could not retrieve passwords encrypted with the Windows API (we have to be on the same context as the user to decrypt these passwords). Only few passwords could be retrieved (Firefox, Jitsi, Dbvis, etc.).

Build your own password recovery script
----
It's possible to write your own script for the software of your choice. Building your own module has become extremely easy. 

To do that, some code standards are to be met: 
* Create a class using the name of the software containing 2 importants functions:
	* init: used to define all arguments used to launch the class. 
	* run:  will be the main function

* Add on the config.manageModules.py file your class name and your import

* The run function has to return an array of dictionnaries
	* ex: [{"Username": "emiliano", "Password":"ZapaTa", "URL": "http://mail.com"}]

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
	* Microsoft Visual C++ 2010 Redistributable Package (x86): https://www.microsoft.com/en-us/download/details.aspx?id=5555

* For Linux	
	* Python 2.7
	* Argparse
	* PyCrypto: https://www.dlitz.net/software/pycrypto/
	* Dbus (Pidgin)
	* Pyasn1 (for ASN1 decoding): https://pypi.python.org/pypi/pyasn1/
	* Python Gnome keyring: apt-get install python-gnomekeyring
	* Python-kde4 (Kwallet): apt-get install python-kde4

----
| __Alessandro ZANNI__    |
| ------------- |
| __zanni.alessandro@gmail.com__  |

