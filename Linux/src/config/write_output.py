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
	footer = '\n[+] %s passwords have been found.\n\n' % str(constant.nbPasswordFound)
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
	footer = '\n[+] %s passwords have been found.\n' % str(constant.nbPasswordFound)
	if logging.getLogger().isEnabledFor(logging.INFO) == False:
		footer += 'For more information launch it again with the -v option\n'
	print footer

# print output if passwords have been found
def print_output(software_name, pwdFound):
	if pwdFound:
		# if the debug logging level is not apply => print the title
		if logging.getLogger().isEnabledFor(logging.INFO) == False:
			Header().title(software_name)
		
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
				# Store all passwords found on a table => for dictionary attack if master password set
				constant.nbPasswordFound += 1
				try:
					if password:
						constant.passwordFound.append(pwd['Password'].strip())
					elif key:
						constant.passwordFound.append(pwd['key'])
				except:
					pass
			
			for p in pwd.keys():
				print '%s: %s' % (p, pwd[p])
			print
		
		# write credentials into a text file
		checks_write(toWrite, software_name)
	else:
		logging.info("[!] No passwords found\n")


def print_debug(error_level, message):
	
	b = bcolors()

	# print when password is found
	if error_level == 'OK':
		print b.OK + message + b.ENDC

	# print when password is not found
	elif error_level == 'FAILED':
		print b.FAIL + message + b.ENDC

	# print messages depending of their criticism
	elif error_level == 'CRITICAL':
		logging.error(b.FAIL + '[CRITICAL] ' + message + '\n' + b.ENDC)

	elif error_level == 'ERROR':
		logging.error(b.FAIL + '[ERROR] ' + message + '\n' + b.ENDC)
	
	elif error_level == 'WARNING':
		logging.warning(b.WARNING + message + '\n' + b.ENDC)
	
	elif error_level == 'DEBUG':
		logging.debug(message + '\n')

	elif error_level == 'INFO':
		logging.info(message + '\n')
	
	else:
		logging.info('[%s] %s' % (error_level, message))

# --------------------------- End of output functions ---------------------------