# browsers
from lazagne.softwares.browsers.mozilla import Mozilla

def get_categories():
	category = {
		'browsers': {'help': 'Web browsers supported'},
		'mails': {'help': 'Email clients supported'},
	}
	return category

def get_modules():
	moduleNames = [
		Mozilla(),
	]
	return moduleNames
