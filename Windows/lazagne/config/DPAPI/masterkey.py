#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
- DPAPICK : https://bitbucket.org/jmichel/dpapick
- DPAPILAB : https://github.com/dfirfpi/dpapilab
"""

from . import crypto
from .credhist import CredHistFile
from .system import CredSystem
from .eater import DataStruct, Eater
from collections import defaultdict

import codecs
import hashlib
import struct
import os

from lazagne.config.constant import constant


class MasterKey(DataStruct):
    """
    This class represents a MasterKey block contained in a MasterKeyFile
    """

    def __init__(self, raw=None):
        self.decrypted = False
        self.key = None
        self.key_hash = None
        self.hmacSalt = None
        self.hmac = None
        self.hmacComputed = None
        self.cipherAlgo = None
        self.hashAlgo = None
        self.rounds = None
        self.iv = None
        self.version = None
        self.ciphertext = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.iv = data.eat("16s")
        self.rounds = data.eat("L")
        self.hashAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.cipherAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.ciphertext = data.remain()

    def decrypt_with_hash(self, sid, pwdhash):
        """
        Decrypts the masterkey with the given user's hash and SID.
        Simply computes the corresponding key then calls self.decrypt_with_key()
        """
        self.decrypt_with_key(crypto.derivePwdHash(pwdhash=pwdhash, sid=sid))

    def decrypt_with_password(self, sid, pwd):
        """
        Decrypts the masterkey with the given user's password and SID.
        Simply computes the corresponding key, then calls self.decrypt_with_hash()
        """
        try:
            pwd = pwd.encode("UTF-16LE")
        except Exception:
            return

        for algo in ["sha1", "md4"]:
            self.decrypt_with_hash(sid=sid, pwdhash=hashlib.new(algo, pwd).digest())
            if self.decrypted:
                break

    def decrypt_with_key(self, pwdhash):
        """
        Decrypts the masterkey with the given encryption key.
        This function also extracts the HMAC part of the decrypted stuff and compare it with the computed one.
        Note that, once successfully decrypted, the masterkey will not be decrypted anymore; this function will simply return.
        """
        if self.decrypted or not pwdhash:
            return

        # Compute encryption key
        cleartxt = crypto.dataDecrypt(self.cipherAlgo, self.hashAlgo, self.ciphertext, pwdhash, self.iv,
                                      self.rounds)
        self.key = cleartxt[-64:]
        hmacSalt = cleartxt[:16]
        hmac = cleartxt[16:16 + int(self.hashAlgo.digestLength)]
        hmacComputed = crypto.DPAPIHmac(self.hashAlgo, pwdhash, hmacSalt, self.key)
        self.decrypted = hmac == hmacComputed
        if self.decrypted:
            self.key_hash = hashlib.sha1(self.key).digest()


class CredHist(DataStruct):
    """This class represents a Credhist block contained in the MasterKeyFile"""

    def __init__(self, raw=None):
        self.version = None
        self.guid = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.guid = b"%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")


class DomainKey(DataStruct):
    """This class represents a DomainKey block contained in the MasterKeyFile.

    Currently does nothing more than parsing. Work on Active Directory stuff is
    still on progress.

    """

    def __init__(self, raw=None):
        self.version = None
        self.secretLen = None
        self.accesscheckLen = None
        self.guidKey = None
        self.encryptedSecret = None
        self.accessCheck = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        self.secretLen = data.eat("L")
        self.accesscheckLen = data.eat("L")
        self.guidKey = b"%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % data.eat("L2H8B")  # data.eat("16s")
        self.encryptedSecret = data.eat("%us" % self.secretLen)
        self.accessCheck = data.eat("%us" % self.accesscheckLen)


class MasterKeyFile(DataStruct):
    """
    This class represents a masterkey file.
    """

    def __init__(self, raw=None):
        self.masterkey = None
        self.backupkey = None
        self.credhist = None
        self.domainkey = None
        self.decrypted = False
        self.version = None
        self.guid = None
        self.policy = None
        self.masterkeyLen = self.backupkeyLen = self.credhistLen = self.domainkeyLen = 0
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        data.eat("2L")
        self.guid = data.eat("72s").replace(b"\x00", b"")
        data.eat("2L")
        self.policy = data.eat("L")
        self.masterkeyLen = data.eat("Q")
        self.backupkeyLen = data.eat("Q")
        self.credhistLen = data.eat("Q")
        self.domainkeyLen = data.eat("Q")

        if self.masterkeyLen > 0:
            self.masterkey = MasterKey()
            self.masterkey.parse(data.eat_sub(self.masterkeyLen))
        if self.backupkeyLen > 0:
            self.backupkey = MasterKey()
            self.backupkey.parse(data.eat_sub(self.backupkeyLen))
        if self.credhistLen > 0:
            self.credhist = CredHist()
            self.credhist.parse(data.eat_sub(self.credhistLen))
        if self.domainkeyLen > 0:
            self.domainkey = DomainKey()
            self.domainkey.parse(data.eat_sub(self.domainkeyLen))

    def get_key(self):
        """
        Returns the first decrypted block between Masterkey and BackupKey.
        If none has been decrypted, returns the Masterkey block.
        """
        if self.masterkey.decrypted:
            return self.masterkey.key or self.masterkey.key_hash
        elif self.backupkey.decrypted:
            return self.backupkey.key
        return self.masterkey.key

    def jhash(self, sid=None, context='local'):
        """
        Compute the hash used to be bruteforced.
        From the masterkey field of the mk file => mk variable.
        """
        if 'des3' in str(self.masterkey.cipherAlgo).lower() and 'hmac' in str(self.masterkey.hashAlgo).lower():
            version = 1
            hmac_algo = 'sha1'
            cipher_algo = 'des3'

        elif 'aes-256' in str(self.masterkey.cipherAlgo).lower() and 'sha512' in str(self.masterkey.hashAlgo).lower():
            version = 2
            hmac_algo = 'sha512'
            cipher_algo = 'aes256'

        else:
            return 'Unsupported combination of cipher {cipher_algo} and hash algorithm {algo} found!'.format(
                cipher_algo=self.masterkey.cipherAlgo, algo=self.masterkey.hashAlgo)

        context_int = 0
        if context == "domain":
            context_int = 2
        elif context == "local":
            context_int = 1

        return '$DPAPImk${version}*{context}*{sid}*{cipher_algo}*{hmac_algo}*{rounds}*{iv}*{size}*{ciphertext}'.format(
            version=version,
            context=context_int,
            sid=sid,
            cipher_algo=cipher_algo,
            hmac_algo=hmac_algo,
            rounds=self.masterkey.rounds,
            iv=self.masterkey.iv.encode("hex"),
            size=len(self.masterkey.ciphertext.encode("hex")),
            ciphertext=self.masterkey.ciphertext.encode("hex")
        )


class MasterKeyPool(object):
    """
    This class is the pivot for using DPAPIck.
    It manages all the DPAPI structures and contains all the decryption intelligence.
    """

    def __init__(self):
        self.keys = defaultdict(
            lambda: {
                'password': None,  # contains cleartext password
                'mkf': [],  # contains the masterkey file object
            }
        )
        self.mkfiles = []
        self.credhists = {}
        self.mk_dir = None
        self.nb_mkf = 0
        self.nb_mkf_decrypted = 0
        self.preferred_guid = None
        self.system = None

    def add_master_key(self, mkey):
        """
        Add a MasterKeyFile is the pool.
        mkey is a string representing the content of the file to add.
        """
        mkf = MasterKeyFile(mkey)
        self.keys[mkf.guid]['mkf'].append(mkf)

        # Store mkfile object
        self.mkfiles.append(mkf)  # TO DO000000 => use only self.keys variable

    def load_directory(self, directory):
        """
        Adds every masterkey contained in the given directory to the pool.
        """
        if os.path.exists(directory):
            self.mk_dir = directory
            for k in os.listdir(directory):
                try:
                    with open(os.path.join(directory, k), 'rb') as f:
                        self.add_master_key(f.read())
                        self.nb_mkf += 1
                except Exception:
                    pass
            return True
        return False

    def get_master_keys(self, guid):
        """
        Returns an array of Masterkeys corresponding to the given GUID.
        """
        return self.keys.get(guid, {}).get('mkf')

    def get_password(self, guid):
        """
        Returns the password found corresponding to the given GUID.
        """
        return self.keys.get(guid, {}).get('password')

    def add_credhist_file(self, sid, credfile):
        """
        Adds a Credhist file to the pool.
        """
        if os.path.exists(credfile):
            try:
                with open(credfile) as f:
                    self.credhists[sid] = CredHistFile(f.read())
            except Exception:
                pass

    def get_preferred_guid(self):
        """
        Extract from the Preferred file the associated GUID.
        This guid represent the preferred masterkey used by the system.
        This means that it has been encrypted using the current password not an older one.
        """
        if self.preferred_guid:
            return self.preferred_guid

        if self.mk_dir:
            preferred_file = os.path.join(self.mk_dir, u'Preferred')
            if os.path.exists(preferred_file):
                with open(preferred_file, 'rb') as pfile:
                    GUID1 = pfile.read(8)
                    GUID2 = pfile.read(8)

                GUID = struct.unpack("<LHH", GUID1)
                GUID2 = struct.unpack(">HLH", GUID2)
                self.preferred_guid = b"%s-%s-%s-%s-%s%s" % (
                format(GUID[0], '08x'), format(GUID[1], '04x'), format(GUID[2], '04x'), format(GUID2[0], '04x'),
                format(GUID2[1], '08x'), format(GUID2[2], '04x'))
                return self.preferred_guid.encode()

        return False

    def get_cleartext_password(self, guid=None):
        """
        Get cleartext password if already found of the associated guid.
        If not guid specify, return the associated password of the preferred guid.
        """
        if not guid:
            guid = self.get_preferred_guid()

        if guid:
            return self.get_password(guid)

    def get_dpapi_hash(self, sid, context='local'):
        """
        Extract the DPAPI hash corresponding to the user's password to be able to bruteforce it using john or hashcat.
        No admin privilege are required to extract it.
        :param context: expect local or domain depending of the windows environment.
        """

        self.get_preferred_guid()

        for mkf in self.mkfiles:
            if self.preferred_guid == mkf.guid:
                return mkf.jhash(sid=sid, context=context)

    def add_system_credential(self, blob):
        """
        Adds DPAPI_SYSTEM token to the pool.
        blob is a string representing the LSA secret token
        """
        self.system = CredSystem(blob)

    def try_credential(self, sid, password=None):
        """
        This function tries to decrypt every masterkey contained in the pool that has not been successfully decrypted yet with the given password and SID.
        Should be called as a generator (ex: for r in try_credential(sid, password))
        """

        # Check into cache to gain time (avoid checking twice the same thing)
        if constant.dpapi_cache.get(sid): 
            if constant.dpapi_cache[sid]['password'] == password: 
                if constant.dpapi_cache[sid]['decrypted']: 
                    return True, ''
                else:
                    return False, ''

        # All master key files have not been already decrypted
        if self.nb_mkf_decrypted != self.nb_mkf:
            for guid in self.keys:
                for mkf in self.keys[guid].get('mkf', ''):
                    if not mkf.decrypted:
                        mk = mkf.masterkey
                        if mk:
                            mk.decrypt_with_password(sid, password)
                            if not mk.decrypted and self.credhists.get(sid) is not None:
                                # Try using credhist file
                                self.credhists[sid].decrypt_with_password(password)
                                for credhist in self.credhists[sid].entries_list:
                                    mk.decrypt_with_hash(sid, credhist.pwdhash)
                                    if credhist.ntlm is not None and not mk.decrypted:
                                        mk.decrypt_with_hash(sid, credhist.ntlm)

                                    if mk.decrypted:
                                        yield u'masterkey {masterkey} decrypted using credhists key'.format(
                                            masterkey=mk.guid.decode())
                                        self.credhists[sid].valid = True

                            constant.dpapi_cache[sid] = {
                                'password': password,
                                'decrypted': mk.decrypted
                            }

                            if mk.decrypted:
                                # Save the password found
                                self.keys[mkf.guid]['password'] = password
                                mkf.decrypted = True
                                self.nb_mkf_decrypted += 1

                                yield True, u'{password} ok for masterkey {masterkey}'.format(password=password,
                                                                                              masterkey=mkf.guid.decode())

                            else:
                                yield False, u'{password} not ok for masterkey {masterkey}'.format(password=password,
                                                                                                   masterkey=mkf.guid.decode())

    def try_credential_hash(self, sid, pwdhash=None):
        """
        This function tries to decrypt every masterkey contained in the pool that has not been successfully decrypted yet with the given password and SID.
        Should be called as a generator (ex: for r in try_credential_hash(sid, pwdhash))
        """

        # All master key files have not been already decrypted
        if self.nb_mkf_decrypted != self.nb_mkf:
            for guid in self.keys:
                for mkf in self.keys[guid].get('mkf', ''):
                    if not mkf.decrypted:
                        mk = mkf.masterkey
                        mk.decrypt_with_hash(sid, pwdhash)
                        if not mk.decrypted and self.credhists.get(sid) is not None:
                            # Try using credhist file
                            self.credhists[sid].decrypt_with_hash(pwdhash)
                            for credhist in self.credhists[sid].entries_list:
                                mk.decrypt_with_hash(sid, credhist.pwdhash)
                                if credhist.ntlm is not None and not mk.decrypted:
                                    mk.decrypt_with_hash(sid, credhist.ntlm)

                                if mk.decrypted:
                                    yield True, u'masterkey {masterkey} decrypted using credhists key'.format(
                                        masterkey=mk.guid)
                                    self.credhists[sid].valid = True
                                    break

                        if mk.decrypted:
                            mkf.decrypted = True
                            self.nb_mkf_decrypted += 1
                            yield True, u'{hash} ok for masterkey {masterkey}'.format(hash=codecs.encode(pwdhash, 'hex').decode(),
                                                                                      masterkey=mkf.guid.decode())
                        else:
                            yield False, u'{hash} not ok for masterkey {masterkey}'.format(
                                hash=codecs.encode(pwdhash, 'hex').decode(), masterkey=mkf.guid.decode())

    def try_system_credential(self):
        """
        Decrypt masterkey files from the system user using DPAPI_SYSTEM creds as key
        Should be called as a generator (ex: for r in try_system_credential())
        """
        for guid in self.keys:
            for mkf in self.keys[guid].get('mkf', ''):
                if not mkf.decrypted:
                    mk = mkf.masterkey
                    mk.decrypt_with_key(self.system.user)
                    if not mk.decrypted:
                        mk.decrypt_with_key(self.system.machine)

                    if mk.decrypted:
                        mkf.decrypted = True
                        self.nb_mkf_decrypted += 1

                        yield True, u'System masterkey decrypted for {masterkey}'.format(masterkey=mkf.guid.decode())
                    else:
                        yield False, u'System masterkey not decrypted for masterkey {masterkey}'.format(
                            masterkey=mkf.guid.decode())
