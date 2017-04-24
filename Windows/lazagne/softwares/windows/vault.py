from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
from ctypes.wintypes import *

class Vault(ModuleInfo):
	def __init__(self):
		options = {'command': '-vault', 'action': 'store_true', 'dest': 'Vault', 'help': 'Vault manager (Win8 or higher)'}
		ModuleInfo.__init__(self, 'Vault passwords (Internet Explorer, etc.)', 'windows', options, cannot_be_impersonate_using_tokens=False)

	def run(self, software_name = None):
		if float(get_os_version()) <= 6.1:
			print_debug('DEBUG', 'Vault not supported for this OS')
			return

		pwdFound 	= []
		cbVaults 	= DWORD()
		vaults 		= LPGUID()
		hVault 		= HANDLE(INVALID_HANDLE_VALUE)
		cbItems 	= DWORD()
		items 		= c_char_p()

		if vaultEnumerateVaults(0, byref(cbVaults), byref(vaults)) == 0:
			if cbVaults.value == 0:
				print_debug('INFO', 'No Vaults found') 
				return
			else:
				for i in range(cbVaults.value):
					if vaultOpenVault(byref(vaults[i]), 0, byref(hVault)) == 0:
						if hVault:
							if vaultEnumerateItems(hVault, 0x200, byref(cbItems), byref(items)) == 0:
								
								for j in range(cbItems.value):
									
									items8 = cast(items, POINTER(VAULT_ITEM_WIN8))
									pItem8 = PVAULT_ITEM_WIN8()
									try:
										values = {
											'URL' 	: str(items8[j].pResource.contents.data.string),
											'Username' 	: str(items8[j].pUsername.contents.data.string)
										}
										if items8[j].pName:		
											values['Name'] = items8[j].pName

										if vaultGetItem8(hVault, byref(items8[j].id), items8[j].pResource, items8[j].pUsername, items8[j].unknown0, None, 0, byref(pItem8)) == 0:
											password = pItem8.contents.pPassword.contents.data.string
											if password:
												values['Password'] = password

										pwdFound.append(values)

									except Exception, e:
										print_debug('DEBUG', str(e))

									if pItem8:
										vaultFree(pItem8)

								if items:
									vaultFree(items)
						
							vaultCloseVault(byref(hVault))
				
				vaultFree(vaults)

		return pwdFound
