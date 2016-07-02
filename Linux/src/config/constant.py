
class constant():
	folder_name = 'results'
	file_name_results = 'credentials' # the extention is added depending on the user output choice
	MAX_HELP_POSITION = 27
	CURRENT_VERSION = '1.1'
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
