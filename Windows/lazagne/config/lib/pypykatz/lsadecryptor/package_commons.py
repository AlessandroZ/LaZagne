import logging

from abc import abstractmethod
from ..commons.common import hexdump
from ..commons.win_datatypes import RTL_AVL_TABLE


class Logger:
	def __init__(self, module_name, package_name, sysinfo):
		self.package_name = package_name
		self.module_name = module_name
		self.sysinfo = sysinfo
		self.logger = logging.getLogger('pypykatz')
		
	def get_level(self):
		return self.logger.getEffectiveLevel()
		
	def log(self, msg, loglevel = 1):
		first = True
		for line in msg.split('\n'):
			if first == True:
				self.logger.log(loglevel, '[%s] [%s] %s' % (self.package_name, self.module_name, line))
				first = False
			else:
				self.logger.log(loglevel, '[%s] [%s]    %s' % (self.package_name, self.module_name, line))


class PackageTemplate(object):
	def __init__(self, package_name, sysinfo=None):
		self.logger = Logger('template', package_name, sysinfo)
		self.package_name = package_name
		self.sysinfo = sysinfo
		
	def log(self, msg, loglevel = 6):
		self.logger.log(loglevel, '%s' % msg)
	
	def log_template(self, struct_var_name, struct_template_obj, loglevel = 6):
		""""
		Generic logging function to show which template was selected for which structure
		"""
		self.logger.log('Selecting template for %s: %s' % (struct_var_name, struct_template_obj.__name__), loglevel)

	@staticmethod
	@abstractmethod
	def get_template(sysinfo):
		pass
		

class PackageDecryptor(object):
	def __init__(self, package_name, lsa_decryptor, sysinfo, reader):
		self.logger = Logger('decryptor', package_name, sysinfo)
		self.package_name = package_name
		self.lsa_decryptor = lsa_decryptor
		self.sysinfo = sysinfo
		self.reader = reader
	
	def log(self, msg, loglevel=6):
		self.logger.log('%s' % msg, loglevel)
		
	def find_signature(self, module_name, signature):
		"""
		Searches for a sequence of bytes in the module identified by module_name
		"""
		self.log('Searching for key struct signature')
		fl = self.reader.find_in_module(module_name,self.decryptor_template.signature)
		if len(fl) == 0:
			raise Exception('Signature was not found in module %s Signature: %s' % (module_name, self.decryptor_template.signature.hex()))
		return fl[0]
		
	def log_ptr(self, ptr, name, datasize=None):
		"""
		Reads datasize bytes from the memory region pointed by the pointer.
		ptr = the pointer to be read
		name = display name for the memory structure, usually the data structure's name the pointer is pointing at
		"""
		level = self.logger.get_level()
		if level > 6 or level == 0:
			return
			
		if not datasize:
			if level == 5:
				datasize = 0x10
			if level == 4:
				datasize = 0x20
			if level == 3:
				datasize = 0x50
			if level == 2:
				datasize = 0x100
			if level == 1:
				datasize = 0x200			
			
		pos = self.reader.tell()
		try:
			self.reader.move(ptr)
			data = self.reader.peek(datasize)
			self.reader.move(pos)
			self.log('%s: %s\n%s' % (name, hex(ptr), hexdump(data, start = ptr)))
		except Exception as e:
			self.log('%s: Logging failed for position %s' % (name, hex(ptr)))

	def decrypt_password(self, enc_password, bytes_expected = False, trim_zeroes = True):
		"""
		Common decryption method for LSA encrypted passwords. Result be string or hex encoded bytes (for machine accounts).
		Also supports bad data, as orphaned credentials may contain actual password OR garbage
		
		enc_password: bytes The encrypted password bytes
		bytes_expected: bool :indication that the result of decryption is bytes, no need for encoding
		trim_zeroes: bool: if a text is expected then this variable tells wether we should trim the trailing zeroes after decryption
		"""
		dec_password = None
		if len(enc_password) % 8 == 0:  # checking if encrypted password is of correct blocksize
			temp = self.lsa_decryptor.decrypt(enc_password)
			if temp and len(temp) > 0:
				if bytes_expected == False:
					try: # normal password
						dec_password = temp.decode('utf-16-le')
					except Exception:  # machine password
						dec_password = temp.hex()
					else:  # if not machine password, then check if we should trim it
						if trim_zeroes == True:
							dec_password = dec_password.rstrip('\x00')
				else:
					dec_password = temp
		
		else:  # special case for (unusable/plaintext?) orphaned credentials
			dec_password = enc_password
		
		return dec_password
		
	def walk_avl(self, node_ptr, result_ptr_list):
		"""
		Walks the AVL tree, extracts all OrderedPointer values and returns them in a list
		node_ptr: POINTER : the Parent->RightChild pointer in the AVL tree
		result_ptr_list: list: the list to store the results in
		"""
		node = node_ptr.read(self.reader, override_finaltype=RTL_AVL_TABLE)
		if node is None:
			self.log('AVL walker found empty tree')
			return
		if node.OrderedPointer.value != 0:
			result_ptr_list.append(node.OrderedPointer.value)
			if node.BalancedRoot.LeftChild.value != 0 :
				self.walk_avl(node.BalancedRoot.LeftChild, result_ptr_list)
			if node.BalancedRoot.RightChild.value != 0 :
				self.walk_avl(node.BalancedRoot.RightChild, result_ptr_list)
		
	def walk_list(self, entry_ptr, callback, max_walk = 255, override_ptr = None):
		"""
		Iterating over a linked list. Linked lists in packages are circural, so the end of the list is tested is the Flink is pointing to an address already seen.
		
		entry_ptr = pointer type object the will yiled the first entry when called read()
		callback = function that will be called when a new entry is found. callback method will be invoked with one parameter, the entry itself
		
		max_walk = limit the amount of entries to be iterating
		override_ptr = if this parameter is set the pointer will be resolved as if it would be pointing to this structure
		"""
		
		# if entry_ptr.value == 0:
		#	self.log('walk_list called with a NULL pointer! This could mean that parsing is failing, double check this!')
		#	return
		
		entries_seen = {entry_ptr.location : 1}
		max_walk = max_walk
		self.log_ptr(entry_ptr.value, 'List entry -%s-' % entry_ptr.finaltype.__name__ if not override_ptr else override_ptr.__name__)
		while True:
			if override_ptr:
				entry = entry_ptr.read(self.reader, override_ptr)
			else:
				entry = entry_ptr.read(self.reader)

			if not entry:
				break

			callback(entry)
			max_walk -= 1
			self.log('%s next ptr: %x' % (entry.Flink.finaltype.__name__ if not override_ptr else override_ptr.__name__ , entry.Flink.value))
			self.log('%s seen: %s' % (entry.Flink.finaltype.__name__ if not override_ptr else override_ptr.__name__ , entry.Flink.value not in entries_seen))
			self.log('%s max_walk: %d' % (entry.Flink.finaltype.__name__ if not override_ptr else override_ptr.__name__ , max_walk))
			if entry.Flink.value != 0 and entry.Flink.value not in entries_seen and max_walk != 0:
				entries_seen[entry.Flink.value] = 1
				self.log_ptr(entry.Flink.value, 'Next list entry -%s-' % entry.Flink.finaltype.__name__ if not override_ptr else override_ptr.__name__)
				entry_ptr = entry.Flink
			else:
				break
