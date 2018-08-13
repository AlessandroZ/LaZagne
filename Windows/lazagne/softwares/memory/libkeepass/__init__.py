# -*- coding: utf-8 -*-
import io
from contextlib import contextmanager

from .common import read_signature
# from kdb3 import KDB3Reader, KDB3_SIGNATURE
from .kdb4 import KDB4Reader, KDB4_SIGNATURE

BASE_SIGNATURE = 0x9AA2D903

_kdb_readers = {
    # KDB3_SIGNATURE[1]: KDB3Reader,
    #0xB54BFB66: KDB4Reader, # pre2.x may work, untested
    KDB4_SIGNATURE[1]: KDB4Reader,
    }

@contextmanager
def open(filename, **credentials):
    """
    A contextmanager to open the KeePass file with `filename`. Use a `password`
    and/or `keyfile` named argument for decryption.
    
    Files are identified using their signature and a reader suitable for 
    the file format is intialized and returned.
    
    Note: `keyfile` is currently not supported for v3 KeePass files.
    """
    kdb = None
    try:
        with io.open(filename, 'rb') as stream:
            signature = read_signature(stream)
            cls = get_kdb_reader(signature)
            kdb = cls(stream, **credentials)
            yield kdb
            kdb.close()
    except Exception:
        if kdb: kdb.close()
        raise

def add_kdb_reader(sub_signature, cls):
    """
    Add or overwrite the class used to process a KeePass file.
    
    KeePass uses two signatures to identify files. The base signature is 
    always `0x9AA2D903`. The second/sub signature varies. For example
    KeePassX uses the v3 sub signature `0xB54BFB65` and KeePass2 the v4 sub 
    signature `0xB54BFB67`.
    
    Use this method to add or replace a class by givin a `sub_signature` as
    integer and a class, which should be a subclass of 
    `keepass.common.KDBFile`.
    """
    _kdb_readers[sub_signature] = cls

def get_kdb_reader(signature):
    """
    Retrieve the class used to process a KeePass file by `signature`, which
    is a a tuple or list with two elements. The first being the base signature 
    and the second the sub signature as integers.
    """
    if signature[0] != BASE_SIGNATURE:
        raise IOError('Unknown base signature.')
    
    if signature[1] not in _kdb_readers:
        raise IOError('Unknown sub signature.')
    
    return _kdb_readers[signature[1]]

