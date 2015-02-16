
The LaZagne Project !!!

Description
The LaZagne project is an application used to retrieve lots of passwords stored on a local computer. 
Each software stores its passwords using different technics (plaintext, using api, custom algorithms, etc.). This tool has been developped to find these passwords for most common softwares. 
At this moment, it supports 22 softwares on windows and 12 on a linux plateform.

Usage
- Launch all modules
Cmd: laZagne.exe all

- Launch only a specific module
Cmd: laZagne.exe <module_name>
Example: laZagne.exe browsers
Help: laZagne.exe -h

- Launch only a specific software script
Cmd: laZagne.exe <module_name> <software>
Example: laZagne.exe browsers -f
Help: laZagne.exe browsers -h

- Write all passwords found into a file (-w options)
Cmd: laZagne.exe all -w


Supported softwares
Windows
	- browsers
		firefox
		chrome
		opera
		ie

	- chats
		skype
		pidgin
		jitsi

	- mails
		thunderbird
		outlook

	- adminsys
		filezilla
		puttycm
		winscp
		cyberduck
		coreFTP
		FTPNavigator

	- database
		sqldeveloper
		squirrel
		dbvisualizer

	- svn
		tortoise

	- wifi
		wifi

	- windows credentials
		Domain visible network (.Net Passport)
		generic network credentials

Linux
	- browsers
		firefox
		opera

	- chats
		pidgin
		jitsi

	- mails
		thunderbird

	- adminsys
		filezilla
		environment variables

	- database
		sqldeveloper
		squirrel
		dbvisualizer

	- wifi
		network manager

	- wallet
		gnome keyring


IE Browser history
	Internet Explorer passwords (from ie7 and before windows 8) can only be decrypted using the URL of the website. This one is used as an argument of the Win32CryptUnprotectData api. So to decrypt it, it is necessary to retreive the browser history of ie. 
To do that, I have used C code. So I used a dll (the code is on on the "browser_history_dll" directory) and it is directly embedded to the python code as a base64 string (c.f. ie.py). Once launched, the dll is written to the disk, a wrapper is used to call dll functions and then the dll file is removed from the disk.

Build your own module
If you want to improve this tool, it is possible to build your own module. You could send me your script of the sotware of your choice and it will be added to this project. 
Some syntax requirements are needed: 
	- Create a class using the name of the software
	- This class has to have a function called "retrieve_password" (it will be the main function)
	- The output containing all passwords has to be send to the "print_output" function - ex: print_output(<software_name>, password_list)
		- password_list has to be an array of dictionnaries. 
	- Optional: you could use the function "print_debug" to print your output - ex: print_debug("ERROR", "Failed to load ...")
	- Use an existing script to understand what I have said :)

Requirements
To execute the source code, some external library are required.
	- For Windows
		- Wconio (for the color)
			http://newcenturycomputers.net/projects/wconio.html
			http://newcenturycomputers.net/projects/download.cgi/WConio-1.5.win32-py2.7.exe

		- Python for Windows Extensions
			http://sourceforge.net/projects/pywin32/

	- For Linux
		- None => VOIR IMPORT CRYPTO !!!!!!!!!!!!!!!

Author:
Alessandro ZANNI


 

