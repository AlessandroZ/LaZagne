import logging
from colorama import init, Fore, Back, Style

class Header():
	def __init__(self):
		init() # for colorama
	
	def first_title(self):
		init()
		print Style.BRIGHT + Fore.WHITE
		print '|====================================================================|'
		print '|                                                                    |'
		print '|                        The LaZagne Project                         |'
		print '|                                                                    |'
		print '|                          ! BANG BANG !                             |'
		print '|                                                                    |'
		print '|====================================================================|'
		print Style.RESET_ALL
	
	# info option for the logging
	def title(self, title):
		print Style.BRIGHT + Fore.WHITE + '------------------- ' + title + ' passwords -----------------\n' + Style.RESET_ALL
		
	# Subtitle
	def title1(self, title1):
		print Style.BRIGHT + Fore.WHITE + '[*] ' + title1 + '\n' + Style.RESET_ALL

	# debug option for the logging
	def title_info(self, title):
		logging.info(Style.BRIGHT + Fore.WHITE + '------------------- ' + title + ' passwords -----------------\n' + Style.RESET_ALL)
