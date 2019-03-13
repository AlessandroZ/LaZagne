# -*- coding: utf-8 -*-
import base64
import gzip
import io
import xml.etree.ElementTree as ElementTree
import zlib
import codecs

from .common import KDBFile, HeaderDictionary
from .common import stream_unpack
from .crypto import transform_key, pad, unpad
from .crypto import xor, sha256, aes_cbc_decrypt, aes_cbc_encrypt
from .hbio import HashedBlockIO
from .pureSalsa20 import Salsa20


KDB4_SALSA20_IV = codecs.decode('e830094b97205d2a', 'hex')
KDB4_SIGNATURE = (0x9AA2D903, 0xB54BFB67)

try:
    file_types = (file, io.IOBase)
except NameError:
    file_types = (io.IOBase,)


class KDB4Header(HeaderDictionary):
    fields = {
        'EndOfHeader': 0,
        'Comment': 1,
        # cipher used for the data stream after the header
        'CipherID': 2,
        # indicates whether decrypted data stream is gzip compressed
        'CompressionFlags': 3,
        # 
        'MasterSeed': 4,
        # 
        'TransformSeed': 5,
        # 
        'TransformRounds': 6,
        # 
        'EncryptionIV': 7,
        # key used to protect data in xml
        'ProtectedStreamKey': 8,
        # first 32 bytes of the decrypted data stream after the header
        'StreamStartBytes': 9,
        # cipher used to protect data in xml (ARC4 or Salsa20)
        'InnerRandomStreamID': 10,
    }

    fmt = {3: '<I', 6: '<q'}


class KDB4File(KDBFile):
    def __init__(self, stream=None, **credentials):
        self.header = KDB4Header()
        KDBFile.__init__(self, stream, **credentials)

    def set_compression(self, flag=1):
        """Dis- (0) or enable (default: 1) compression"""
        if flag not in [0, 1]:
            raise ValueError('Compression flag can be 0 or 1.')
        self.header.CompressionFlags = flag

    # def set_comment(self, comment):
    #    self.header.Comment = comment

    def read_from(self, stream):
        """
        Read, parse, decrypt, decompress a KeePass file from a stream.
        
        :arg stream: A file-like object (opened in 'rb' mode) or IO buffer
            containing a KeePass file.
        """
        super(KDB4File, self).read_from(stream)
        if self.header.CompressionFlags == 1:
            self._unzip()

    # def write_to(self, stream):
    #     """
    #     Write the KeePass database back to a KeePass2 compatible file.
        
    #     :arg stream: A writeable file-like object or IO buffer.
    #     """
    #     if not (isinstance(stream, io.IOBase) or isinstance(stream, file_types)):
    #         raise TypeError('Stream does not have the buffer interface.')

    #     self._write_header(stream)

    def _read_header(self, stream):
        """
        Parse the header and write the values into self.header. Also sets
        self.header_length.
        """
        # KeePass 2.07 has version 1.01,
        # 2.08 has 1.02,
        # 2.09 has 2.00, 2.10 has 2.02, 2.11 has 2.04,
        # 2.15 has 3.00.
        # The first 2 bytes are critical (i.e. loading will fail, if the
        # file version is too high), the last 2 bytes are informational.
        # TODO implement version check

        # the first header field starts at byte 12 after the signature
        stream.seek(12)

        while True:
            # field_id is a single byte
            field_id = stream_unpack(stream, None, 1, 'b')

            # field_id >10 is undefined
            if field_id not in self.header.fields.values():
                raise IOError('Unknown header field found.')

            # two byte (short) length of field data
            length = stream_unpack(stream, None, 2, 'h')
            if length > 0:
                data = stream_unpack(stream, None, length, '{}s'.format(length))
                self.header.b[field_id] = data

            # set position in data stream of end of header
            if field_id == 0:
                self.header_length = stream.tell()
                break

    # def _write_header(self, stream):
    #     """Serialize the header fields from self.header into a byte stream, prefix
    #     with file signature and version before writing header and out-buffer
    #     to `stream`.

    #     Note, that `stream` is flushed, but not closed!"""
    #     # serialize header to stream
    #     header = bytearray()
    #     # write file signature
    #     header.extend(struct.pack('<II', *KDB4_SIGNATURE))
    #     # and version
    #     header.extend(struct.pack('<hh', 0, 3))

    #     field_ids = self.header.keys()
    #     field_ids.sort()
    #     field_ids.reverse() # field_id 0 must be last
    #     for field_id in field_ids:
    #         value = self.header.b[field_id]
    #         length = len(value)
    #         header.extend(struct.pack('<b', field_id))
    #         header.extend(struct.pack('<h', length))
    #         header.extend(struct.pack('{}s'.format(length), value))

    #     # write header to stream
    #     stream.write(header)

    #     headerHash = base64.b64encode(sha256(header))
    #     self.obj_root.Meta.HeaderHash = headerHash

    #     # create HeaderHash if it does not exist
    #     if len(self.obj_root.Meta.xpath("HeaderHash")) < 1:
    #         etree.SubElement(self.obj_root.Meta, "HeaderHash")

    #     # reload out_buffer because we just changed the HeaderHash
    #     self.protect()
    #     self.out_buffer = io.BytesIO(self.pretty_print())

    #     # zip or not according to header setting
    #     if self.header.CompressionFlags == 1:
    #         self._zip()

    #     self._encrypt();

    #     # write encrypted block to stream
    #     stream.write(self.out_buffer)
    #     stream.flush()

    def _decrypt(self, stream):
        """
        Build the master key from header settings and key-hash list.
        
        Start reading from `stream` after the header and decrypt all the data.
        Remove padding as needed and feed into hashed block reader, set as
        in-buffer.
        """
        super(KDB4File, self)._decrypt(stream)

        data = aes_cbc_decrypt(stream.read(), self.master_key,
                               self.header.EncryptionIV)
        data = unpad(data)

        length = len(self.header.StreamStartBytes)
        if self.header.StreamStartBytes == data[:length]:
            # skip startbytes and wrap data in a hashed block io
            self.in_buffer = HashedBlockIO(bytes=data[length:])
            # set successful decryption flag
            self.opened = True
        else:
            raise IOError('Master key invalid.')

    def _encrypt(self):
        """
        Rebuild the master key from header settings and key-hash list. Encrypt
        the stream start bytes and the out-buffer formatted as hashed block
        stream with padding added as needed.
        """
        # rebuild master key from (possibly) updated header
        self._make_master_key()

        # make hashed block stream
        block_buffer = HashedBlockIO()
        block_buffer.write(self.out_buffer.read())
        # data is buffered in hashed block io, start a new one
        self.out_buffer = io.BytesIO()
        # write start bytes (for successful decrypt check)
        self.out_buffer.write(self.header.StreamStartBytes)
        # append blocked data to out-buffer
        block_buffer.write_block_stream(self.out_buffer)
        block_buffer.close()
        self.out_buffer.seek(0)

        # encrypt the whole thing with header settings and master key
        data = pad(self.out_buffer.read())
        self.out_buffer = aes_cbc_encrypt(data, self.master_key,
                                          self.header.EncryptionIV)

    def _unzip(self):
        """
        Inplace decompress in-buffer. Read/write position is moved to 0.
        """
        self.in_buffer.seek(0)
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.in_buffer = io.BytesIO(d.decompress(self.in_buffer.read()))
        self.in_buffer.seek(0)

    def _zip(self):
        """
        Inplace compress out-buffer. Read/write position is moved to 0.
        """
        data = self.out_buffer.read()
        self.out_buffer = io.BytesIO()
        # note: compresslevel=6 seems to be important for kdb4!
        gz = gzip.GzipFile(fileobj=self.out_buffer, mode='wb', compresslevel=6)
        gz.write(data)
        gz.close()
        self.out_buffer.seek(0)

    def _make_master_key(self):
        """
        Make the master key by (1) combining the credentials to create 
        a composite hash, (2) transforming the hash using the transform seed
        for a specific number of rounds and (3) finally hashing the result in 
        combination with the master seed.
        """
        super(KDB4File, self)._make_master_key()
        composite = sha256(''.join(self.keys))
        tkey = transform_key(composite,
                             self.header.TransformSeed,
                             self.header.TransformRounds)
        self.master_key = sha256(self.header.MasterSeed + tkey)


class KDBXmlExtension:
    """
    The KDB4 payload is a XML document. For easier use this class provides
    a lxml.objectify'ed version of the XML-tree as the `obj_root` attribute.
    
    More importantly though in the XML document text values can be protected
    using Salsa20. Protected elements are unprotected by default (passwords are
    in clear). You can override this with the `unprotect=False` argument.
    """

    def __init__(self, unprotect=True):
        self._salsa_buffer = bytearray()
        self.salsa = Salsa20(
            sha256(self.header.ProtectedStreamKey),
            KDB4_SALSA20_IV)

        self.in_buffer.seek(0)
        # self.tree = objectify.parse(self.in_buffer)
        # self.obj_root = self.tree.getroot()
        self.obj_root = ElementTree.fromstring(self.in_buffer.read())

        if unprotect:
            self.unprotect()

    def unprotect(self):
        """
        Find all elements with a 'Protected=True' attribute and replace the text
        with an unprotected value in the XML element tree. The original text is
        set as 'ProtectedValue' attribute and the 'Protected' attribute is set
        to 'False'. The 'ProtectPassword' element in the 'Meta' section is also
        set to 'False'.
        """
        self._reset_salsa()
        for elem in self.obj_root.iterfind('.//Value[@Protected="True"]'):
            if elem.text is not None:
                elem.set('ProtectedValue', elem.text)
                elem.set('Protected', 'False')
                elem.text = self._unprotect(elem.text)

    # def protect(self):
    #     """
    #     Find all elements with a 'Protected=False' attribute and replace the
    #     text with a protected value in the XML element tree. If there was a
    #     'ProtectedValue' attribute, it is deleted and the 'Protected' attribute
    #     is set to 'True'. The 'ProtectPassword' element in the 'Meta' section is
    #     also set to 'True'.

    #     This does not just restore the previous protected value, but reencrypts
    #     all text values of elements with 'Protected=False'. So you could use
    #     this after modifying a password, adding a completely new entry or
    #     deleting entry history items.
    #     """
    #     self._reset_salsa()
    #     self.obj_root.Meta.MemoryProtection.ProtectPassword._setText('True')
    #     for elem in self.obj_root.iterfind('.//Value[@Protected="False"]'):
    #         etree.strip_attributes(elem, 'ProtectedValue')
    #         elem.set('Protected', 'True')
    #         elem._setText(self._protect(elem.text))

    # def pretty_print(self):
    #     """Return a serialization of the element tree."""
    #     return etree.tostring(self.obj_root, pretty_print=True, 
    #         encoding='utf-8', standalone=True)

    def to_dic(self):
        """Return a dictionnary of the element tree."""
        pwd_found = []
        # print etree.tostring(self.obj_root)
        root = ElementTree.fromstring(ElementTree.tostring(self.obj_root))
        for entry in root.findall('.//Root//Entry'):
            dic = {}
            for elem in entry.iter('String'):
                try:
                    if elem[0].text == 'UserName':
                        dic['Login'] = elem[1].text
                    else:
                        # Replace new line by a point
                        dic[elem[0].text] = elem[1].text.replace('\n', '.')
                except Exception as e:
                    # print e
                    pass
            pwd_found.append(dic)
        return pwd_found

    # def write_to(self, stream):
    #     """Serialize the element tree to the out-buffer."""
    #     if self.out_buffer is None:
    #         self.protect()
    #         self.out_buffer = io.BytesIO(self.pretty_print())

    def _reset_salsa(self):
        """Clear the salsa buffer and reset algorithm counter to 0."""
        self._salsa_buffer = bytearray()
        self.salsa.set_counter(0)

    def _get_salsa(self, length):
        """
        Returns the next section of the "random" Salsa20 bytes with the 
        requested `length`.
        """
        while length > len(self._salsa_buffer):
            new_salsa = self.salsa.encrypt_bytes(str(bytearray(64)))
            self._salsa_buffer.extend(new_salsa)
        nacho = self._salsa_buffer[:length]
        del self._salsa_buffer[:length]
        return nacho

    def _unprotect(self, string):
        """
        Base64 decode and XOR the given `string` with the next salsa.
        Returns an unprotected string.
        """
        tmp = base64.b64decode(string)
        return str(xor(tmp, self._get_salsa(len(tmp))))

    def _protect(self, string):
        """
        XORs the given `string` with the next salsa and base64 encodes it.
        Returns a protected string.
        """
        tmp = str(xor(string, self._get_salsa(len(string))))
        return base64.b64encode(tmp)


class KDB4Reader(KDB4File, KDBXmlExtension):
    """
    Usually you would want to use the `keepass.open` context manager to open a
    file. It checks the file signature and creates a suitable reader-instance.
    
    doing it by hand is also possible::
    
        kdb = keepass.KDB4Reader()
        kdb.add_credentials(password='secret')
        with open('passwords.kdb', 'rb') as fh:
            kdb.read_from(fh)
    
    or...::
    
        with open('passwords.kdb', 'rb') as fh:
            kdb = keepass.KDB4Reader(fh, password='secret')
    
    """

    def __init__(self, stream=None, **credentials):
        KDB4File.__init__(self, stream, **credentials)

    def read_from(self, stream, unprotect=True):
        KDB4File.read_from(self, stream)
        # the extension requires parsed header and decrypted self.in_buffer, so
        # initialize only here
        KDBXmlExtension.__init__(self, unprotect)

    # def write_to(self, stream, use_etree=True):
    #     """
    #     Write the KeePass database back to a KeePass2 compatible file.

    #     :arg stream: A file-like object or IO buffer.
    #     :arg use_tree: Serialize the element tree to XML to save (default:
    #         True), Set to False to write the data currently in the in-buffer
    #         instead.
    #     """
    #     if use_etree:
    #         KDBXmlExtension.write_to(self, stream)
    #     KDB4File.write_to(self, stream)
