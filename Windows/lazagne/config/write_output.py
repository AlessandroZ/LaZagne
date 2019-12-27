# -*- coding: utf-8 -*-
import ctypes
import getpass
import json
import logging
import os
import socket
import sys
import traceback

from time import gmtime, strftime
from platform import uname

from lazagne.config.users import get_username_winapi
from lazagne.config.winstructure import string_to_unicode, char_to_int, chr_or_byte, python_version
from .constant import constant

# --------------------------- Standard output functions ---------------------------

STD_OUTPUT_HANDLE = -11
std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
tmp_user = None


class StandardOutput(object):
    def __init__(self):
        self.banner = '''
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|
'''
        self.FILTER = b''.join([((len(repr(chr_or_byte(x))) == 3 and python_version == 2) or
                                 (len(repr(chr_or_byte(x))) == 4 and python_version == 3))
                                and chr_or_byte(x) or b'.' for x in range(256)])

    def set_color(self, color='white', intensity=False):
        c = {'white': 0x07, 'red': 0x04, 'green': 0x02, 'cyan': 0x03}.get(color, None)

        if intensity:
            c |= 0x08

        ctypes.windll.kernel32.SetConsoleTextAttribute(std_out_handle, c)

    # print banner
    def first_title(self):
        self.do_print(message=self.banner, color='white', intensity=True)
        # Python 3.7.3 on Darwin x86_64: i386
        python_banner = 'Python {}.{}.{} on'.format(*sys.version_info) + " {0} {4}: {5}\n".format(*uname())
        self.print_logging(function=logging.debug, message=python_banner, prefix='[!]', color='white', intensity=True)

    # info option for the logging
    def print_title(self, title):
        t = u'------------------- ' + title + ' passwords -----------------\n'
        self.do_print(message=t, color='white', intensity=True)

    # debug option for the logging
    def title_info(self, title):
        t = u'------------------- ' + title + ' passwords -----------------\n'
        self.print_logging(function=logging.info, prefix='', message=t, color='white', intensity=True)

    def print_user(self, user, force_print=False):
        if logging.getLogger().isEnabledFor(logging.INFO) or force_print:
            self.do_print(u'\n########## User: {user} ##########\n'.format(user=user))

    def print_footer(self, elapsed_time=None):
        footer = '\n[+] %s passwords have been found.\n' % str(constant.nb_password_found)
        if not logging.getLogger().isEnabledFor(logging.INFO):
            footer += 'For more information launch it again with the -v option\n'
        if elapsed_time:
            footer += '\nelapsed time = ' + str(elapsed_time)
        self.do_print(footer)

    def print_hex(self, src, length=8):
        N = 0
        result = b''
        while src:
            s, src = src[:length], src[length:]
            hexa = b' '.join([b"%02X" % char_to_int(x) for x in s])
            s = s.translate(self.FILTER)
            result += b"%04X   %-*s   %s\n" % (N, length * 3, hexa, s)
            N += length
        return result

    def try_unicode(self, obj, encoding='utf-8'):
        if python_version == 3:
            try:
                return obj.decode()
            except Exception:
                return obj
        try:
            if isinstance(obj, basestring):       # noqa: F821
                if not isinstance(obj, unicode):  # noqa: F821
                    obj = unicode(obj, encoding)  # noqa: F821
        except UnicodeDecodeError:
            return repr(obj)
        return obj

    # centralize print function
    def do_print(self, message='', color=False, intensity=False):
        # quiet mode => nothing is printed
        if constant.quiet_mode:
            return

        message = self.try_unicode(message)
        if color:
            self.set_color(color=color, intensity=intensity)
            self.print_without_error(message)
            self.set_color()
        else:
            self.print_without_error(message)

    def print_without_error(self, message):
        try:
            print(message.decode())
        except Exception:
            try:
                print(message)
            except Exception:
                print(repr(message))

    def print_logging(self, function, prefix='[!]', message='', color=False, intensity=False):
        if constant.quiet_mode:
            return

        try:
            msg = u'{prefix} {msg}'.format(prefix=prefix, msg=message)
        except Exception:
            msg = '{prefix} {msg}'.format(prefix=prefix, msg=str(message))

        if color:
            self.set_color(color, intensity)
            function(msg)
            self.set_color()
        else:
            function(msg)

    def print_output(self, software_name, pwd_found):
        if pwd_found:
            # if the debug logging level is not apply => print the title
            if not logging.getLogger().isEnabledFor(logging.INFO):
                # print the username only if password have been found
                user = constant.finalResults.get('User', '')
                global tmp_user
                if user != tmp_user:
                    tmp_user = user
                    self.print_user(user, force_print=True)

                # if not title1:
                self.print_title(software_name)

            # Particular passwords representation
            to_write = []
            if software_name in ('Hashdump', 'Lsa_secrets', 'Mscache'):
                pwds = pwd_found[1]
                for pwd in pwds:
                    self.do_print(pwd)
                    if software_name == 'Lsa_secrets':
                        hex_value = self.print_hex(pwds[pwd], length=16)
                        to_write.append([pwd.decode(), hex_value.decode()])
                        self.do_print(hex_value)
                    else:
                        to_write.append(pwd)
                self.do_print()

            # Other passwords
            else:
                # Remove duplicated password
                pwd_found = [dict(t) for t in set([tuple(d.items()) for d in pwd_found])]

                # Loop through all passwords found
                for pwd in pwd_found:

                    # Detect which kinds of password has been found
                    pwd_lower_keys = {k.lower(): v for k, v in pwd.items()}
                    for p in ('password', 'key', 'hash'):
                        pwd_category = [s for s in pwd_lower_keys if p in s]
                        if pwd_category:
                            pwd_category = pwd_category[0]
                            break

                    write_it = False
                    passwd = None
                    try:
                        passwd_str = pwd_lower_keys[pwd_category]
                        # Do not print empty passwords
                        if not passwd_str:
                            continue

                        passwd = string_to_unicode(passwd_str)
                    except Exception:
                        pass

                    # No password found
                    if not passwd:
                        print_debug("FAILED", u'Password not found !!!')
                    else:
                        constant.nb_password_found += 1
                        write_it = True
                        print_debug("OK", u'{pwd_category} found !!!'.format(
                            pwd_category=pwd_category.title()))

                        # Store all passwords found on a table => for dictionary attack if master password set
                        if passwd not in constant.password_found:
                            constant.password_found.append(passwd)

                    pwd_info = []
                    for p in pwd:
                        try:
                            pwd_line = '%s: %s' % (p, pwd[p].decode())  # Manage bytes output (py 3)
                        except Exception:
                            pwd_line = '%s: %s' % (p, pwd[p])

                        pwd_info.append(pwd_line)
                        self.do_print(pwd_line)

                    self.do_print()

                    if write_it:
                        to_write.append(pwd_info)

            # write credentials into a text file
            self.checks_write(to_write, software_name)
        else:
            print_debug("INFO", "No passwords found\n")

    def write_header(self):
        time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        try:
            hostname = socket.gethostname().decode(sys.getfilesystemencoding())
        except AttributeError:
            hostname = socket.gethostname()

        header = u'{banner}\r\n- Date: {date}\r\n- Username: {username}\r\n- Hostname:{hostname}\r\n\r\n'.format(
            banner=self.banner.replace('\n', '\r\n'),
            date=str(time),
            username=get_username_winapi(),
            hostname=hostname
        )
        with open(os.path.join(constant.folder_name, '{}.txt'.format(constant.file_name_results)), "ab+") as f:
            f.write(header.encode())

    def write_footer(self):
        footer = '\n[+] %s passwords have been found.\r\n\r\n' % str(constant.nb_password_found)
        open(os.path.join(constant.folder_name, '%s.txt' % constant.file_name_results), "a+").write(footer)

    def checks_write(self, values, category):
        if values:
            if 'Passwords' not in constant.finalResults:
                constant.finalResults['Passwords'] = []
            constant.finalResults['Passwords'].append((category, values))


def print_debug(error_level, message):
    # Quiet mode => nothing is printed
    if constant.quiet_mode:
        return

    # print when password is found
    if error_level == 'OK':
        constant.st.do_print(message='[+] {message}'.format(message=message), color='green')

    # print when password is not found
    elif error_level == 'FAILED':
        constant.st.do_print(message='[-] {message}'.format(message=message), color='red', intensity=True)

    elif error_level == 'CRITICAL' or error_level == 'ERROR':
        constant.st.print_logging(function=logging.error, prefix='[-]', message=message, color='red', intensity=True)

    elif error_level == 'WARNING':
        constant.st.print_logging(function=logging.warning, prefix='[!]', message=message, color='cyan')

    elif error_level == 'DEBUG':
        constant.st.print_logging(function=logging.debug, message=message, prefix='[!]')

    else:
        constant.st.print_logging(function=logging.info, message=message, prefix='[!]')

# --------------------------- End of output functions ---------------------------

def json_to_string(json_string):
    string = u''
    try:
        for json in json_string:
            if json:
                string += u'##################  User: {username} ################## \r\n'.format(username=json['User'])
                if 'Passwords' not in json:
                    string += u'\r\nNo passwords found for this user !\r\n\r\n'
                else:
                    for pwd_info in json['Passwords']:
                        category, pwds_tab = pwd_info

                        string += u'\r\n------------------- {category} -----------------\r\n'.format(
                            category=category)

                        if category.lower() in ('lsa_secrets', 'hashdump', 'cachedump'):
                            for pwds in pwds_tab:
                                if category.lower() == 'lsa_secrets':
                                    for d in pwds:
                                        string += u'%s\r\n' % (constant.st.try_unicode(d))
                                else:
                                    string += u'%s\r\n' % (constant.st.try_unicode(pwds))
                        else:
                            for pwds in pwds_tab:
                                string += u'\r\nPassword found !!!\r\n'
                                for pwd in pwds:
                                    try:
                                        name, value = pwd.split(':', 1)
                                        string += u'%s: %s\r\n' % (
                                            name.strip(), constant.st.try_unicode(value.strip()))
                                    except Exception:
                                        print_debug('DEBUG', traceback.format_exc())
                        string += u'\r\n'
    except Exception:
        print_debug('ERROR', u'Error parsing the json results: {error}'.format(error=traceback.format_exc()))

    return string


def write_in_file(result):
    """
    Write output to file (json and txt files)
    """
    if result:
        if constant.output in ('json', 'all'):
            try:
                # Human readable Json format
                pretty_json = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '), ensure_ascii=False)
                with open(os.path.join(constant.folder_name, constant.file_name_results + '.json'), 'ab+') as f:
                    f.write(pretty_json.encode())

                constant.st.do_print(u'[+] File written: {file}'.format(
                    file=os.path.join(constant.folder_name, constant.file_name_results + '.json'))
                )
            except Exception as e:
                print_debug('DEBUGG', traceback.format_exc())

        if constant.output in ('txt', 'all'):
            try:
                with open(os.path.join(constant.folder_name, constant.file_name_results + '.txt'), 'ab+') as f:
                    a = json_to_string(result)
                    f.write(a.encode())

                constant.st.write_footer()
                constant.st.do_print(u'[+] File written: {file}'.format(
                    file=os.path.join(constant.folder_name, constant.file_name_results + '.txt'))
                )
            except Exception as e:
                print_debug('DEBUG', traceback.format_exc())
