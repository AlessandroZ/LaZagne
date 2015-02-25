import constant
import os
from time import gmtime, strftime
import getpass
import socket
from config.header import Header
from config.color import bcolors
from config.constant import constant
import logging

# --------------------------- Functions used to write ---------------------------

def write_header():
	time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
	header = '''|====================================================================|
|                                                                    |
|                       Credentsials discovery                       |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|\n
- Date: ''' + time + '''
- Username: ''' + getpass.getuser() + '''
- Hostname: ''' + socket.gethostname() + ''' \n
------------------------------ Results ------------------------------\n'''

	open(constant.folder_name + os.sep + 'credentials.txt',"a+b").write(header)

def write_footer():
	footer = '\n[+] %s passwords have been found.\nFor more information launch it again  with the -v option\n\n' % str(constant.nbPasswordFound)
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


def print_debug(error_level, message):
	
	b = bcolors()
	if error_level == 'ERROR':
		logging.debug(b.FAIL + '[ERROR] ' + message + '\n' + b.ENDC)
	
	elif error_level == 'WARNING':
		logging.debug(b.WARNING + '[WARNING] ' + message + '\n' + b.ENDC)
	
	elif error_level == 'INFO':
		logging.debug('[INFO] ' + message + '\n')
	
	# print when password is not found
	elif error_level == 'FAILED':
		logging.info(b.FAIL + message + b.ENDC)
	
	# print when password is found
	elif error_level == 'OK':
		logging.info(b.OK + message + b.ENDC)
		
	elif error_level == 'DEBUG':
		logging.debug(message + '\n')
	
	else:
		logging.debug('[%s] %s' % (error_level, message))

# --------------------------- End of output functions ---------------------------