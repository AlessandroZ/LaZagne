import WConio
import logging

class Header():
	def first_title(self):
		WConio.textcolor(WConio.WHITE)
		print
		print '|====================================================================|'
		print '|                                                                    |'
		print '|                        The LaZagne Project                         |'
		print '|                                                                    |'
		print '|                          ! BANG BANG !                             |'
		print '|                                                                    |'
		print '|====================================================================|'
		print
		WConio.textcolor(WConio.LIGHTGREY)
	
	# info option for the logging
	def title_info(self, title):
		WConio.textcolor(WConio.WHITE)
		logging.info("------------------- %s passwords -----------------\n" % title)
		WConio.textcolor(WConio.LIGHTGREY)

	# debug option for the logging
	def title_debug(self, title):
		WConio.textcolor(WConio.WHITE)
		logging.debug("------------------- %s passwords -----------------\n" % title)
		WConio.textcolor(WConio.LIGHTGREY)

