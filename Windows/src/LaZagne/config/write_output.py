from constant import constant
from time import gmtime, strftime
import os, getpass, socket
import logging
import WConio
from config.header import Header

# --------------------------- Functions used to write ---------------------------

def write_header():
	time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
	header = '''|====================================================================|\r\n
|                                                                    |\r\n
|                       Credentsials discovery                       |\r\n
|                                                                    |\r\n
|                          ! BANG BANG !                             |\r\n
|                                                                    |\r\n
|====================================================================|\r\n\r\n
- Date: ''' + time + '''\n\r
- Username: ''' + getpass.getuser() + ''' \r\n
- Hostname: ''' + socket.gethostname() + ''' \r\n\r\n
------------------------------ Results ------------------------------\r\n\r\n'''

	open(constant.folder_name + os.sep + 'credentials.txt',"a+b").write(header)

def write_footer():
	footer = '\n[+] %s passwords have been found.\r\nFor more information launch it again  with the -v option\r\n\r\n' % str(constant.nbPasswordFound)
	open(constant.folder_name + os.sep + 'credentials.txt',"a+b").write(footer)
	
def write_credentials(pwdFound, category):
	tmp = "############ %s passwords ############\r\n\r\n" % category
	for pwd in pwdFound:
		for p in pwd.keys():
			tmp = str(tmp) + str(p) + ": " + str(pwd[p]) + "\r\n"
		tmp = str(tmp) + "\r\n"
	open(constant.folder_name + os.sep + 'credentials.txt',"a+b").write(tmp)
	
def checks_write(values, category):
	if values:
		if constant.output == 'txt':
			try:
				write_credentials(values, category)
				logging.info('[+] Credentials stored successfully on the file: %s\\credentials.txt\n' % constant.folder_name)
			except:
				logging.info('Couldn\'t write the results file\n')

# --------------------------- End of functions used to write ---------------------------

# --------------------------- Output functions ---------------------------
def print_footer():
	footer = '\n[+] %s passwords have been found.\nFor more information launch it again with the -v option\n' % str(constant.nbPasswordFound)
	logging.info(footer)

# print output if passwords have been found
def print_output(software_name, pwdFound):
	if pwdFound:
		# if the debug logging level is not apply => print the title
		if logging.getLogger().isEnabledFor(logging.DEBUG) == False:
			Header().title_info(software_name)
		
		toWrite = []
		for pwd in pwdFound:
			lower_list = [s.lower() for s in pwd.keys()]
			password = [s for s in lower_list if "password" in s]
			key = [s for s in lower_list if "key" in s] # for the wifi
			
			# No password found
			if not password and not key:
				print_debug("FAILED", "Password not found !!!")
			else:
				print_debug("OK", "Password found !!!")
				toWrite.append(pwd)
				constant.nbPasswordFound += 1
			
			for p in pwd.keys():
				logging.info("%s: %s" % (p, pwd[p]))
			print
		
		# write credentials into a text file
		checks_write(toWrite, software_name)
	else:
		logging.debug("[!] No passwords found\n")

def print_error(message):
	WConio.textcolor(WConio.LIGHTRED)
	logging.debug('[!] %s\n' % message)
	WConio.textcolor(WConio.LIGHTGREY)

# def print_debug(message):
	# logging.debug('[!] %s\n' % message)
	
def print_debug(error_level, message):
	if error_level == 'ERROR':
		WConio.textcolor(WConio.LIGHTRED)
		logging.debug('[ERROR] %s\n' % message)
		WConio.textcolor(WConio.LIGHTGREY)
	
	elif error_level == 'INFO':
		logging.debug('[INFO] %s\n' % message)
	
	# print when password is not found
	elif error_level == 'FAILED':
		WConio.textcolor(WConio.LIGHTRED)
		logging.info(message)
		WConio.textcolor(WConio.LIGHTGREY)
		
	# print when password is found
	elif error_level == 'OK':
		WConio.textcolor(WConio.GREEN)
		logging.info(message)
		WConio.textcolor(WConio.LIGHTGREY)
		
	elif error_level == 'DEBUG':
		logging.debug('%s\n' % message)
	
	else:
		logging.debug('[%s] %s' % (error_level, message))

# --------------------------- End of output functions ---------------------------