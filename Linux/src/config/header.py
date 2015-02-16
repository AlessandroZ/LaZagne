from color import bcolors
import logging

class Header():
	def first_title(self):
		print bcolors().WARNING
		print '|====================================================================|'
		print '|                                                                    |'
		print '|                        The LaZagne Project                         |'
		print '|                                                                    |'
		print '|                          ! BANG BANG !                             |'
		print '|                                                                    |'
		print '|====================================================================|'
		print bcolors().ENDC
		
		
	def title(self, title):
		print bcolors().WARNING
		print "------------------- " +  title + " passwords -----------------"
		print bcolors().ENDC
	
	# info option for the logging
	def title_info(self, title):
		b = bcolors()
		logging.info(b.WARNING + "------------------- " + title + " passwords -----------------\n" + b.ENDC)

	# debug option for the logging
	def title_debug(self, title):
		b = bcolors()
		logging.debug(b.WARNING + "------------------- " + title + " passwords -----------------\n" + b.ENDC )