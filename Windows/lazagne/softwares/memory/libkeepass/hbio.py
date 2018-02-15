# -*- coding: utf-8 -*-
import io
import struct
import hashlib

# default from KeePass2 source
BLOCK_LENGTH = 1024*1024
#HEADER_LENGTH = 4+32+4

def read_int(stream, length):
    try:
        return struct.unpack('<I', stream.read(length))[0]
    except:
        return None

class HashedBlockIO(io.BytesIO):
    """
    The data is stored in hashed blocks. Each block consists of a block index (4
    bytes), the hash (32 bytes) and the block length (4 bytes), followed by the
    block data. The block index starts counting at 0. The block hash is a
    SHA-256 hash of the block data. A block has a maximum length of
    BLOCK_LENGTH, but can be shorter.
    
    Provide a I/O stream containing the hashed block data as the `block_stream`
    argument when creating a HashedBlockReader. Alternatively the `bytes`
    argument can be used to hand over data as a string/bytearray/etc. The data
    is verified upon initialization and an IOError is raised when a hash does
    not match.
    
    HashedBlockReader is a subclass of io.BytesIO. The inherited read, seek, ...
    functions shall be used to access the verified data.
    """
    def __init__(self, block_stream=None, bytes=None):
        io.BytesIO.__init__(self)
        input_stream = None
        if block_stream is not None:
            if not (isinstance(block_stream, io.IOBase) or isinstance(block_stream, file)):
                raise TypeError('Stream does not have the buffer interface.')
            input_stream = block_stream
        elif bytes is not None:
            input_stream = io.BytesIO(bytes)
        if input_stream is not None:
            self.read_block_stream(input_stream)

    def read_block_stream(self, block_stream):
        """
        Read the whole block stream into the self-BytesIO.
        """
        if not (isinstance(block_stream, io.IOBase) or isinstance(block_stream, file)):
            raise TypeError('Stream does not have the buffer interface.')
        while True:
            data = self._next_block(block_stream)
            if not self.write(data):
                break
        self.seek(0)

    def _next_block(self, block_stream):
        """
        Read the next block and verify the data.
        Raises an IOError if the hash does not match.
        """
        index = read_int(block_stream, 4)
        bhash = block_stream.read(32)
        length = read_int(block_stream, 4)
        
        if length > 0:
            data = block_stream.read(length)
            if hashlib.sha256(data).digest() == bhash:
                return data
            else:
                raise IOError('Block hash mismatch error.')
        return bytes()

    def write_block_stream(self, stream, block_length=BLOCK_LENGTH):
        """
        Write all data in this buffer, starting at stream position 0, formatted
        in hashed blocks to the given `stream`.
        
        For example, writing data from one file into another as hashed blocks::
            
            # create new hashed block io without input stream or data
            hb = HashedBlockIO()
            # read from a file, write into the empty hb
            with open('sample.dat', 'rb') as infile:
                hb.write(infile.read())
                # write from the hb into a new file
                with open('hb_sample.dat', 'w') as outfile:
                    hb.write_block_stream(outfile)
        """
        if not (isinstance(stream, io.IOBase) or isinstance(stream, file)):
            raise TypeError('Stream does not have the buffer interface.')
        index = 0
        self.seek(0)
        while True:
            data = self.read(block_length)
            if data:
                stream.write(struct.pack('<I', index))
                stream.write(hashlib.sha256(data).digest())
                stream.write(struct.pack('<I', len(data)))
                stream.write(data)
                index += 1
            else:
                stream.write(struct.pack('<I', index))
                stream.write('\x00'*32)
                stream.write(struct.pack('<I', 0))
                break

