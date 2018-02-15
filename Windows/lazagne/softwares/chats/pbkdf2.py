# -*- coding: utf-8 -*-
"""
    pbkdf2
    ~~~~~~

    This module implements pbkdf2 for Python.  It also has some basic
    tests that ensure that it works.  The implementation is straightforward
    and uses stdlib only stuff and can be easily be copy/pasted into
    your favourite application.

    Use this as replacement for bcrypt that does not need a c implementation
    of a modified blowfish crypto algo.

    Example usage:

    >>> pbkdf2_hex('what i want to hash', 'the random salt')
    'fa7cc8a2b0a932f8e6ea42f9787e9d36e592e0c222ada6a9'

    How to use this:

    1.  Use a constant time string compare function to compare the stored hash
        with the one you're generating::

            def safe_str_cmp(a, b):
                if len(a) != len(b):
                    return False
                rv = 0
                for x, y in izip(a, b):
                    rv |= ord(x) ^ ord(y)
                return rv == 0

    2.  Use `os.urandom` to generate a proper salt of at least 8 byte.
        Use a unique salt per hashed password.

    3.  Store ``algorithm$salt:costfactor$hash`` in the database so that
        you can upgrade later easily to a different algorithm if you need
        one.  For instance ``PBKDF2-256$thesalt:10000$deadbeef...``.


    :copyright: (c) Copyright 2011 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import hmac
import hashlib
from struct import Struct
from operator import xor
from itertools import izip, starmap


_pack_int = Struct('>I').pack


def pbkdf2_hex(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Like :func:`pbkdf2_bin` but returns a hex encoded string."""
    return pbkdf2_bin(data, salt, iterations, keylen, hashfunc).encode('hex')


def pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Returns a binary digest for the PBKDF2 hash algorithm of `data`
    with the given `salt`.  It iterates `iterations` time and produces a
    key of `keylen` bytes.  By default SHA-1 is used as hash function,
    a different hashlib `hashfunc` can be provided.
    """
    hashfunc = hashfunc or hashlib.sha1
    mac = hmac.new(data, None, hashfunc)
    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())
    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = starmap(xor, izip(rv, u))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen]


def test():
    failed = []
    def check(data, salt, iterations, keylen, expected):
        rv = pbkdf2_hex(data, salt, iterations, keylen)
        if rv != expected:
            print 'Test failed:'
            print '  Expected:   %s' % expected
            print '  Got:        %s' % rv
            print '  Parameters:'
            print '    data=%s' % data
            print '    salt=%s' % salt
            print '    iterations=%d' % iterations
            print
            failed.append(1)

    # From RFC 6070
    check('password', 'salt', 1, 20,
          '0c60c80f961f0e71f3a9b524af6012062fe037a6')
    check('password', 'salt', 2, 20,
          'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957')
    check('password', 'salt', 4096, 20,
          '4b007901b765489abead49d926f721d065a429c1')
    check('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
          4096, 25, '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038')
    check('pass\x00word', 'sa\x00lt', 4096, 16,
          '56fa6aa75548099dcc37d7f03425e0c3')
    # This one is from the RFC but it just takes for ages
    ##check('password', 'salt', 16777216, 20,
    ##      'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984')

    # From Crypt-PBKDF2
    check('password', 'ATHENA.MIT.EDUraeburn', 1, 16,
          'cdedb5281bb2f801565a1122b2563515')
    check('password', 'ATHENA.MIT.EDUraeburn', 1, 32,
          'cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837')
    check('password', 'ATHENA.MIT.EDUraeburn', 2, 16,
          '01dbee7f4a9e243e988b62c73cda935d')
    check('password', 'ATHENA.MIT.EDUraeburn', 2, 32,
          '01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86')
    check('password', 'ATHENA.MIT.EDUraeburn', 1200, 32,
          '5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13')
    check('X' * 64, 'pass phrase equals block size', 1200, 32,
          '139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1')
    check('X' * 65, 'pass phrase exceeds block size', 1200, 32,
          '9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a')

    raise SystemExit(bool(failed))


if __name__ == '__main__':
    test()
