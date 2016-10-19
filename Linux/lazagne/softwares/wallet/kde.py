#######################
#
# By Quentin HARDY
#
#######################

import os, sys
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo

class kde(ModuleInfo):
  	def __init__(self):
		options = {'command': '-k', 'action': 'store_true', 'dest': 'kwallet', 'help': 'KWallet'}
		ModuleInfo.__init__(self, 'kwallet', 'wallet', options)
	
	def run(self, software_name = None):		
		if os.getuid() == 0:
			print_debug('INFO', 'Do not run with root privileges)\n')
			return
		try:
		    from PyKDE4.kdeui import KWallet
		    from PyQt4.QtGui import QApplication
		    pwdFound = []
		    app = QApplication([])
		    app.setApplicationName("KWallet")
		    #Get the local wallet
		    f = open(os.devnull, 'w')
		    stdoutBackup = sys.stdout
		    stderrBackup = sys.stderr
		    sys.stdout = f
		    sys.stderr = f
		    wallet = KWallet.Wallet.openWallet(KWallet.Wallet.LocalWallet(), 0)
		    #sys.stdout = stdoutBackup
		    #sys.stderr = stderrBackup
		    #Walk accros folders defined in the KWallet
		    for folder in wallet.folderList():
		      wallet.setFolder(folder)
		      entries = dict()
		      #Get entries for this folder
		      for entry in wallet.entryList():
			      values = {}
			      entries[entry] = wallet.readEntry( entry )
			      values["Folder"] = folder
			      values["Entry"] = entry
			      values["Password"] = (entries[entry][1].toHex().data()).decode('hex').decode('utf-8')[5:]
			      if len(values) != 0:
				pwdFound.append(values)
		    return pwdFound
		except Exception,e:
			print_debug('ERROR', 'An error occurs with KWallet: {0}'.format(e))
			
