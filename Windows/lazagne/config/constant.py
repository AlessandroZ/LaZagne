import time

date = time.strftime("%d%m%Y_%H%M%S")

class constant():
	folder_name = 'results_{current_time}'.format(current_time=date)
	file_name_results = 'credentials' # the extention is added depending on the user output choice
	MAX_HELP_POSITION = 27
	CURRENT_VERSION = '2.0'
	output = None
	file_logger = None

	# jitsi options
	jitsi_masterpass = None

	# mozilla options
	manually = None
	path = None
	bruteforce = None
	specific_path = None
	
	# ie options
	ie_historic = None
	
	# total password found
	nbPasswordFound = 0
	passwordFound = []

	finalResults = {}

	profile = {
		'APPDATA': '',
		'USERPROFILE': '', 
		'HOMEDRIVE': '',
		'HOMEPATH': '',
		'ALLUSERSPROFILE': '', 
		'COMPOSER_HOME': ''
	}
	username = ''

	keepass = {}
	hives = []