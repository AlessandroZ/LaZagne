# from lazagne.config.constant import *
# from write_output import print_debug
# import logging
# import ctypes

# STD_OUTPUT_HANDLE = -11
# std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)

# def setColor(color='white', intensity=False):
# 	c = None
# 	if color == 'white':
# 		c = 0x07
# 	elif color == 'red':
# 		c = 0x04
# 	elif color == 'green':
# 		c = 0x02
# 	elif color == 'cyan':
# 		c = 0x03

# 	if intensity: 
# 		c = c | 0x08

# 	ctypes.windll.kernel32.SetConsoleTextAttribute(std_out_handle, c)

# class Header():
# 	def __init__(self):
# 		# init() # for colorama
# 		self.BRIGHT = '\x1b[31m'
# 		self.WHITE = '\x1b[37m'
# 		self.RESET_COLOR = '\x1b[0m'
	
# 	def first_title(self):
# 		setColor(color='white', intensity=True)
# 		header = '''
# |====================================================================|
# |                                                                    |
# |                        The LaZagne Project                         |
# |                                                                    |
# |                          ! BANG BANG !                             |
# |                                                                    |
# |====================================================================|
# 		'''
# 		if not constant.quiet_mode:
# 			do_print(header)
# 		setColor()
	
# 	# info option for the logging
# 	def title(self, title):
# 		setColor(color='white', intensity=True)
# 		if not constant.quiet_mode:
# 			print '------------------- ' + title + ' passwords -----------------\n'
# 		setColor()
	
# 	# debug option for the logging
# 	def title_info(self, title):
# 		setColor(color='white', intensity=True)
# 		logging.info('------------------- ' + title + ' passwords -----------------\n')
# 		setColor()
