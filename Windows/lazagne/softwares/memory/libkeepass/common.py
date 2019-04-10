# -*- coding: utf-8 -*-
import base64
import codecs
import io
import struct
from xml.etree import ElementTree

from .crypto import sha256

try:
    file_types = (file, io.IOBase)
except NameError:
    file_types = (io.IOBase,)


# file header
class HeaderDictionary(dict):
    """
    A dictionary on steroids for comfortable header field storage and
    manipulation.

    Header fields must be defined in the `fields` property before filling the
    dictionary with data. The `fields` property is a simple dictionary, where
    keys are field names (string) and values are field ids (int)::

        >>> h.fields['rounds'] = 4

    Now you can set and get values using the field id or the field name
    interchangeably::

        >>> h[4] = 3000
        >>> print h['rounds']
        3000
        >>> h['rounds'] = 6000
        >>> print h[4]
        6000

    It is also possible to get and set data using the field name as an
    attribute::

        >>> h.rounds = 9000
        >>> print h[4]
        9000
        >>> print h.rounds
        9000

    For some fields it is more comfortable to unpack their byte value into
    a numeric or character value (eg. the transformation rounds). For those
    fields add a format string to the `fmt` dictionary. Use the field id as
    key::

        >>> h.fmt[4] = '<q'

    Continue setting the value as before if you have it as a number and if you
    need it as a number, get it like before. Only when you have the packed value
    use a different interface::

        >>> h.b.rounds = '\x70\x17\x00\x00\x00\x00\x00\x00'
        >>> print h.b.rounds
        '\x70\x17\x00\x00\x00\x00\x00\x00'
        >>> print h.rounds
        6000

    The `b` (binary?) attribute is a special way to set and get data in its
    packed format, while the usual attribute or dictionary access allows
    setting and getting a numeric value::

        >>> h.rounds = 3000
        >>> print h.b.rounds
        '\xb8\x0b\x00\x00\x00\x00\x00\x00'
        >>> print h.rounds
        3000

    """
    fields = {}
    fmt = {}

    def __init__(self, *args):
        dict.__init__(self, *args)

    def __getitem__(self, key):
        if isinstance(key, int):
            return dict.__getitem__(self, key)
        else:
            return dict.__getitem__(self, self.fields[key])

    def __setitem__(self, key, val):
        if isinstance(key, int):
            dict.__setitem__(self, key, val)
        else:
            dict.__setitem__(self, self.fields[key], val)

    def __getattr__(self, key):
        class wrap(object):
            def __init__(self, d):
                object.__setattr__(self, 'd', d)

            def __getitem__(self, key):
                fmt = self.d.fmt.get(self.d.fields.get(key, key))
                if fmt:
                    return struct.pack(fmt, self.d[key])
                else:
                    return self.d[key]

            __getattr__ = __getitem__

            def __setitem__(self, key, val):
                fmt = self.d.fmt.get(self.d.fields.get(key, key))
                if fmt:
                    self.d[key] = struct.unpack(fmt, val)[0]
                else:
                    self.d[key] = val

            __setattr__ = __setitem__

        if key == 'b':
            return wrap(self)
        try:
            return self.__getitem__(key)
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key, val):
        try:
            return self.__setitem__(key, val)
        except KeyError:
            return dict.__setattr__(self, key, val)


# file baseclass
class KDBFile(object):
    def __init__(self, stream=None, **credentials):
        # list of hashed credentials (pre-transformation)
        self.keys = []
        self.add_credentials(**credentials)

        # the buffer containing the decrypted/decompressed payload from a file
        self.in_buffer = None
        # the buffer filled with data for writing back to a file before
        # encryption/compression
        self.out_buffer = None
        # position in the `in_buffer` where the payload begins
        self.header_length = None
        # decryption success flag, set this to true upon verification of the
        # encryption masterkey. if this is True `in_buffer` must contain
        # clear data.
        self.opened = False

        # the raw/basic file handle, expect it to be closed after __init__!
        if stream is not None:
            if not isinstance(stream, io.IOBase):
                raise TypeError('Stream does not have the buffer interface.')
            self.read_from(stream)

    def read_from(self, stream):
        if not (isinstance(stream, io.IOBase) or isinstance(stream, file_types)):
            raise TypeError('Stream does not have the buffer interface.')
        self._read_header(stream)
        self._decrypt(stream)

    def _read_header(self, stream):
        raise NotImplementedError('The _read_header method was not '
                                  'implemented propertly.')

    def _decrypt(self, stream):
        self._make_master_key()
        # move read pointer beyond the file header
        if self.header_length is None:
            raise IOError('Header length unknown. Parse the header first!')
        stream.seek(self.header_length)

    def write_to(self, stream):
        raise NotImplementedError('The write_to() method was not implemented.')

    def add_credentials(self, **credentials):
        if credentials.get('password'):
            self.add_key_hash(sha256(credentials['password']))
        if credentials.get('keyfile'):
            self.add_key_hash(load_keyfile(credentials['keyfile']))

    def clear_credentials(self):
        """Remove all previously set encryption key hashes."""
        self.keys = []

    def add_key_hash(self, key_hash):
        """
        Add an encryption key hash, can be a hashed password or a hashed
        keyfile. Two things are important: must be SHA256 hashes and sequence is
        important: first password if any, second key file if any.
        """
        if key_hash is not None:
            self.keys.append(key_hash)

    def _make_master_key(self):
        if len(self.keys) == 0:
            raise IndexError('No credentials found.')

    def close(self):
        if self.in_buffer:
            self.in_buffer.close()

    def read(self, n=-1):
        """
        Read the decrypted and uncompressed data after the file header.
        For example, in KDB4 this would be plain, utf-8 xml.

        Note that this is the source data for the lxml.objectify element tree
        at `self.obj_root`. Any changes made to the parsed element tree will
        NOT be reflected in that data stream! Use `self.pretty_print` to get
        XML output from the element tree.
        """
        if self.in_buffer:
            return self.in_buffer.read(n)

    def seek(self, offset, whence=io.SEEK_SET):
        if self.in_buffer:
            return self.in_buffer.seek(offset, whence)

    def tell(self):
        if self.in_buffer:
            return self.in_buffer.tell()


# loading keyfiles
def load_keyfile(filename):
    try:
        return load_xml_keyfile(filename)
    except Exception:
        pass
    try:
        return load_plain_keyfile(filename)
    except Exception:
        pass


def load_xml_keyfile(filename):
    """
    // Sample XML file:
    // <?xml version="1.0" encoding="utf-8"?>
    // <KeyFile>
    //     <Meta>
    //         <Version>1.00</Version>
    //     </Meta>
    //     <Key>
    //         <Data>ySFoKuCcJblw8ie6RkMBdVCnAf4EedSch7ItujK6bmI=</Data>
    //     </Key>
    // </KeyFile>
    """
    with open(filename, 'r') as f:
        # ignore meta, currently there is only version "1.00"
        tree = ElementTree.parse(f).getroot()
        # read text from key, data and convert from base64
        return base64.b64decode(tree.find('Key/Data').text)
    # raise IOError('Could not parse XML keyfile.')


def load_plain_keyfile(filename):
    """
    A "plain" keyfile is a file containing only the key.
    Any other file (JPEG, MP3, ...) can also be used as keyfile.
    """
    with open(filename, 'rb') as f:
        key = f.read()
        # if the length is 32 bytes we assume it is the key
        if len(key) == 32:
            return key
        # if the length is 64 bytes we assume the key is hex encoded
        if len(key) == 64:
            return codecs.decode(key, 'hex')
        # anything else may be a file to hash for the key
        return sha256(key)
    # raise IOError('Could not read keyfile.')


def stream_unpack(stream, offset, length, typecode='I'):
    if offset is not None:
        stream.seek(offset)
    data = stream.read(length)
    return struct.unpack('<' + typecode, data)[0]


def read_signature(stream):
    sig1 = stream_unpack(stream, 0, 4)
    sig2 = stream_unpack(stream, None, 4)
    # ver_minor = stream_unpack(stream, None, 2, 'h')
    # ver_major = stream_unpack(stream, None, 2, 'h')
    # return (sig1, sig2, ver_major, ver_minor)
    return sig1, sig2
