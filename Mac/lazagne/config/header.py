from color import bcolors
import logging

class Header():
	def first_title(self):
		print bcolors().TITLE
		print '|====================================================================|'
		print '|                                                                    |'
		print '|                        The LaZagne Project                         |'
		print '|                                                                    |'
		print '|                          ! BANG BANG !                             |'
		print '|                                                                    |'
		print '|====================================================================|'
		print bcolors().ENDC
		

	# print the title if no logging level has been set
	def title(self, title):
		b = bcolors()
		print b.TITLE + "------------------- " + title + " passwords -----------------\n" + b.ENDC

	# print the title if logging level is higher or equal to info
	def title_info(self, title):
		b = bcolors()
		logging.info(b.TITLE + "------------------- " + title + " passwords -----------------\n" + b.ENDC )