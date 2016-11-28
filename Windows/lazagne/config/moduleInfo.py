# name => Name of a class
# category => windows / browsers / etc
# options => dictionary
#	 - command
#	 - action
#	 - dest
#	 - help
#	ex: ('-s', action='store_true', dest='skype', help='skype')
#		options['command'] = '-s'
#		options['action'] = 'store_true'
#		options['dest'] = 'skype'
#		options['help'] = 'skype'

class ModuleInfo():
	def __init__(self, name, category, options, suboptions = [], need_high_privileges=False, need_to_be_in_env=True):
		self.name = name
		self.category = category
		self.options = options
		self.suboptions = suboptions
		self.need_high_privileges = need_high_privileges
		self.need_to_be_in_env = need_to_be_in_env
	
	def name(self):
		return self.name
	
	def category(self):
		return self.category
	
	def options(self):
		return self.options
	
	def suboptions(self):
		return self.suboptions
	
	def need_high_privileges(self):
		return self.need_high_privileges
	
	def need_to_be_in_env(self):
		return self.need_to_be_in_env