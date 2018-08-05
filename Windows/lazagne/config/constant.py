# -*- coding: utf-8 -*- 
import tempfile
import random
import string
import time
import os

date 	= time.strftime("%d%m%Y_%H%M%S")
tmp  	= tempfile.gettempdir()

class constant():
	folder_name 			= '.'
	file_name_results 		= 'credentials_{current_time}'.format(current_time=date) # the extention is added depending on the user output choice
	MAX_HELP_POSITION		= 27
	CURRENT_VERSION 		= '2.3.2'
	output 					= None
	file_logger 			= None
	
	# ie options
	ie_historic 			= None
	
	# total password found
	nbPasswordFound 		= 0
	passwordFound 			= []
	finalResults			= {}
	profile 				= {
								'APPDATA'			: u'{drive}:\\Users\\{user}\\AppData\\Roaming\\',
								'USERPROFILE'		: u'{drive}:\\Users\\{user}\\',
								'HOMEDRIVE'			: u'{drive}:',
								'HOMEPATH'			: u'{drive}:\\Users\\{user}',
								'ALLUSERSPROFILE'	: u'{drive}:\\ProgramData', 
								'COMPOSER_HOME'		: u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Composer\\', 
								'LOCALAPPDATA'		: u'{drive}:\\Users\\{user}\\AppData\\Local',
							}
	username 				= u''
	keepass 				= {}
	hives 					= {
								'sam' 		:  	os.path.join(tmp, ''.join([random.choice(string.ascii_lowercase) for x in range(0, random.randint(6, 12))])),
								'security'	: 	os.path.join(tmp, ''.join([random.choice(string.ascii_lowercase) for x in range(0, random.randint(6, 12))])),
								'system'	: 	os.path.join(tmp, ''.join([random.choice(string.ascii_lowercase) for x in range(0, random.randint(6, 12))]))
							}
	quiet_mode 				= False
	st 						= None  	# standart output
	drive					= u'C'
	dpapi 					= None
	system_dpapi 			= None
	lsa_secrets				= None
	user_password 			= None
	wifi_password 			= False 	# Check if the module as already be done
	module_to_exec_at_end	= []