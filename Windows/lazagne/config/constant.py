import time

date = time.strftime("%d%m%Y_%H%M%S")

class constant():
	# folder_name 			= 'results_{current_time}'.format(current_time=date)
	folder_name 			= '.'
	file_name_results 		= 'credentials_{current_time}'.format(current_time=date) # the extention is added depending on the user output choice
	MAX_HELP_POSITION		= 27
	CURRENT_VERSION 		= '2.3.1'
	output 					= None
	file_logger 			= None
	# jitsi options
	jitsi_masterpass 		= None

	# mozilla options
	manually 				= None
	path 					= None
	bruteforce 				= None
	specific_path 			= None
	
	# ie options
	ie_historic 			= None
	
	# total password found
	nbPasswordFound 		= 0
	passwordFound 			= []

	finalResults			= {}

	profile = {
		'APPDATA'			: u'',
		'USERPROFILE'		: u'', 
		'HOMEDRIVE'			: u'',
		'HOMEPATH'			: u'',
		'ALLUSERSPROFILE'	: u'', 
		'COMPOSER_HOME'		: u'', 
		'LOCALAPPDATA'		: u''
	}
	username 				= u''

	keepass 				= {}
	hives 					= []

	checkUnattended 		= False

	quiet_mode 				= False

	# standart output
	st 						= None
	drive					= u'C'