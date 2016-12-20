import time

date = time.strftime("%d%m%Y_%H%M%S")

class constant():
	folder_name = 'results_{current_time}'.format(current_time=date)
	file_name_results = 'credentials' # the extention is added depending on the user output choice
	MAX_HELP_POSITION = 27
	CURRENT_VERSION = '1.2'
	output = None
	file_logger = None
	verbose = False
	
	# jitsi options
	jitsi_masterpass = None
	
	# mozilla options
	manually = None
	path = None
	bruteforce = None
	specific_path = None
	mozilla_software = ''

	# total password found
	nbPasswordFound = 0
	passwordFound = []

	finalResults = {}
