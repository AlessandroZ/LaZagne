import constant
import os
from time import gmtime, strftime
import getpass
import socket
from config.header import Header
from config.color import bcolors
from config.constant import constant
import logging
import json

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
	# if values:
	# 	if constant.output == 'txt':
	# 		try:
	# 			write_credentials(values, category)
	# 			logging.info('[+] Credentials stored successfully on the file: %s\\credentials.txt\n' % constant.folder_name)
	# 		except:
	# 			logging.info('Couldn\'t write the results file\n')
	if values:
		if "Passwords" not in constant.finalResults:
			constant.finalResults["Passwords"] = []
		constant.finalResults["Passwords"].append([{"Category": category}, values])

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
		password_category = False
		for pwd in pwdFound:
			# detect which kinds of password has been found
			lower_list = [s.lower() for s in pwd.keys()]
			password = [s for s in lower_list if "password" in s]
			if password: 
				password_category = password
			else:
				key = [s for s in lower_list if "key" in s] # for the wifi
				if key: 
					password_category = key
				else:
					hash = [s for s in lower_list if "hash" in s]
					if hash:
						password_category = hash
			
			# No password found
			if not password_category:
				print_debug("FAILED", "Password not found !!!")
			else:
				print_debug("OK", '%s found !!!' % password_category[0].title())
				toWrite.append(pwd)
				
				# Store all passwords found on a table => for dictionary attack if master password set
				constant.nbPasswordFound += 1
				try:
					constant.passwordFound.append(pwd[password_category[0]])
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

def parseJsonResultToBuffer(jsonString):
	buffer = ''
	try:
		if jsonString:
			buffer += '\r\n\r\n########## User: %s ##########\r\n' % jsonString['User']
			if 'Passwords' not in jsonString:
				buffer += 'No passwords found for this user !'
			else:
				for all_passwords in jsonString['Passwords']:
					# print '- Category: %s' % all_passwords[0]['Category']
					buffer += '------------------- %s -----------------\r\n' % all_passwords[0]['Category']
					for password_by_category in all_passwords[1]:
						buffer += '\r\nPassword found !!!\r\n'
						for dic in password_by_category.keys():
							try:
								buffer += '%s: %s\r\n' % (dic, password_by_category[dic])
							except:
								buffer += '%s: %s\r\n' % (dic, password_by_category[dic].encode('utf-8'))
					buffer += '\r\n'

	except Exception as e:
		print_debug('ERROR', 'Error parsing the json results: %s' % e)
		print_debug('ERROR', 'json content: %s' % jsonString)

	return buffer 