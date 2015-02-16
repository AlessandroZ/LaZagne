import logging
import constant
from color import bcolors

def function_logger(console_level, file_level = None):
	function_name = 'debug'
	logger = logging.getLogger(function_name)
	logger.setLevel(logging.DEBUG) #By default, logs all messages
	
	fh = logging.FileHandler("{0}.log".format(function_name))
	fh.setLevel(file_level)
	fh_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
	fh.setFormatter(fh_format)
	logger.addHandler(fh)
	
	return logger

def print_debug(error_level, message):
	
	b = bcolors()
	
	#if error_level == 'ERROR':
		#print b.FAIL + '[ERROR] ' + message + b.ENDC
		#if constant.verbose:
			#constant.file_logger.error(message)
	#
	#elif error_level == 'WARNING':
		#print b.FAIL + '[WARNING] ' + message + b.ENDC
		#if constant.verbose:
			#constant.file_logger.warning(message)
	#
	#elif error_level == 'INFO':
		#print '[INFO] ' + message
		#if constant.verbose:
			#constant.file_logger.info(message)
	#
	#elif error_level == 'OK':
		#print b.OK + message + b.ENDC
		#if constant.verbose:
			#constant.file_logger.debug(message)
	#
	#elif error_level == 'DEBUG':
		#if constant.verbose:
			#constant.file_logger.debug(message)
	




