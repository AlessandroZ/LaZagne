#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import json
import logging
import getpass
import socket
import sys
import os

from lazagne.config.constant import constant
from platform import uname
from time import gmtime, strftime

from collections import OrderedDict


class Bcolors():
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OK = '\033[92m'
    WARNING = '\033[96m'
    FAIL = '\033[91m'
    TITLE = '\033[93m'
    ENDC = '\033[0m'


class StandardOutput():
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

    def set_color(self, color=None):
        b = Bcolors()
        sys.stdout.write({'white': b.TITLE,
                          'red': b.FAIL,
                          'green': b.OK,
                          'cyan': b.WARNING}.get(color, b.ENDC))

    # Print banner
    def first_title(self):
        self.do_print(message=self.banner, color='white')
        # Python 3.7.3 on Darwin x86_64: i386
        python_banner = 'Python {}.{}.{} on'.format(*sys.version_info) + " {0} {4}: {5}\n".format(*uname())
        self.print_logging(function=logging.debug, prefix='[!]', message=python_banner, color='white')

    # Info option for the logging
    def print_title(self, title):
        t = u'------------------- ' + title + ' passwords -----------------\n'
        self.do_print(message=t, color='white')

    # Debug option for the logging
    def title_info(self, title):
        t = u'------------------- ' + title + ' passwords -----------------\n'
        self.print_logging(function=logging.info, prefix='', message=t, color=False)

    def write_header(self):
        time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        header = u'{banner}\r\n- Date: {date}\r\n- Username: {username}\r\n- Hostname:{hostname}\r\n\r\n'.format(
            banner=self.banner.replace('\n', '\r\n'),
            date=str(time),
            username=getpass.getuser(),
            hostname=socket.gethostname()
        )
        open(os.path.join(constant.folder_name, '{filename}.txt'.format(filename=constant.file_name_results)),
             "a+").write(header)

    def write_footer(self):
        footer = '\n[+] %s passwords have been found.\r\n\r\n' % str(constant.nbPasswordFound)
        open(os.path.join(constant.folder_name, '{filename}.txt'.format(filename=constant.file_name_results)),
             "a+").write(footer)

    def print_footer(self, elapsed_time=None):
        footer = '\n[+] %s passwords have been found.\n' % str(constant.nbPasswordFound)
        if not logging.getLogger().isEnabledFor(logging.INFO):
            footer += 'For more information launch it again with the -v option\n'
        if elapsed_time:
            footer += '\nelapsed time = ' + str(elapsed_time)
        self.do_print(footer)

    def print_logging(self, function, prefix='[!]', message='', color=False):
        if constant.quiet_mode:
            return

        try:
            msg = u'{prefix} {msg}'.format(prefix=prefix, msg=message)
        except Exception:
            msg = '{prefix} {msg}'.format(prefix=prefix, msg=str(message))

        if color:
            self.set_color(color)
            function(msg)
            self.set_color()
        else:
            function(msg)

    def try_unicode(self, obj, encoding='utf-8'):
        try:
            if isinstance(obj, basestring):       # noqa: F821
                if not isinstance(obj, unicode):  # noqa: F821
                    obj = unicode(obj, encoding)  # noqa: F821
        except Exception:
            pass
        return obj

    def print_without_error(self, message):
        try:
            print(message)
        except Exception:
            print(repr(message))

    # Centralize print function
    def do_print(self, message='', color=False):
        # Quiet mode => nothing is printed
        if constant.quiet_mode:
            return

        message = self.try_unicode(message)
        if color:
            self.set_color(color=color)
            self.print_without_error(message)
            self.set_color()
        else:
            self.print_without_error(message)

    def checks_write(self, values, category):
        if values:
            if "Passwords" not in constant.finalResults:
                constant.finalResults["Passwords"] = []
            constant.finalResults["Passwords"].append([{"Category": category}, values])

    def print_output(self, software_name, pwd_found):

        if pwd_found:
            # If the debug logging level is not apply => print the title
            if not logging.getLogger().isEnabledFor(logging.INFO):
                self.print_title(software_name)

            to_write = []

            # Remove duplicated password
            pwd_found = [OrderedDict(t) for t in set([tuple(d.items()) for d in pwd_found])]

            for pwd in pwd_found:
                password_category = False
                # Detect which kinds of password has been found
                lower_list = [s.lower() for s in pwd]
                password = [s for s in lower_list if "password" in s]

                if password:
                    password_category = password
                else:
                    key = [s for s in lower_list if "key" in s]  # for the wifi
                    if key:
                        password_category = key
                    else:
                        hash = [s for s in lower_list if "hash" in s]
                        if hash:
                            password_category = hash
                        else:
                            cmd = [s for s in lower_list if "cmd" in s]
                            if cmd:
                                password_category = cmd

                # Do not print empty passwords
                try:
                    if not pwd[password_category[0].capitalize()]:
                        continue
                except Exception:
                    pass

                # No password found
                if not password_category:
                    print_debug("ERROR", "Password not found !!!")
                else:
                    # Store all passwords found on a table => for dictionary attack if master password set
                    constant.nbPasswordFound += 1
                    passwd = None
                    try:
                        passwd = pwd[password_category[0].capitalize()]
                        if passwd not in constant.passwordFound:
                            constant.passwordFound.append(passwd)
                    except Exception:
                        pass

                    # Password field is empty
                    if not passwd:
                        print_debug("FAILED", u'Password not found !!!')
                    else:
                        print_debug("OK", u'{password_category} found !!!'.format(
                            password_category=password_category[0].title()))
                        to_write.append(pwd)

                for p in pwd:
                    self.do_print('%s: %s' % (p, pwd[p]))
                self.do_print()

            # Write credentials into a text file
            self.checks_write(to_write, software_name)
        else:
            print_debug("INFO", "No passwords found\n")


def print_debug(error_level, message):
    # Quiet mode => nothing is printed
    if constant.quiet_mode:
        return

    # Print when password is found
    if error_level == 'OK':
        constant.st.do_print(message='[+] {message}'.format(message=message), color='green')

    # Print when password is not found
    elif error_level == 'ERROR':
        constant.st.do_print(message='[-] {message}'.format(message=message), color='red')

    elif error_level == 'CRITICAL' or error_level == 'ERROR':
        constant.st.print_logging(function=logging.error, prefix='[-]', message=message, color='red')

    elif error_level == 'WARNING':
        constant.st.print_logging(function=logging.warning, prefix='[!]', message=message, color='cyan')

    elif error_level == 'DEBUG':
        constant.st.print_logging(function=logging.debug, message=message, prefix='[!]')

    else:
        constant.st.print_logging(function=logging.info, message=message, prefix='[!]')


# --------------------------- End of output functions ---------------------------

def parse_json_result_to_buffer(json_string, color=False):
    green = ''
    reset = ''
    title = ''
    if color:
        b = Bcolors()
        green = b.OK
        title = b.TITLE
        reset = b.ENDC

    buffer = ''
    try:
        for json in json_string:
            if json:
                if 'Passwords' not in json:
                    buffer += 'No passwords found for this user !'
                else:
                    for all_passwords in json['Passwords']:
                        buffer += '{title_color}------------------- {password_category} ----------' \
                                  '-------{reset_color}\r\n'.format(
                                                                        title_color=title,
                                                                        password_category=all_passwords[0]['Category'],
                                                                        reset_color=reset
                                                                    )
                        for password_by_category in all_passwords[1]:
                            buffer += '\r\n{green_color}Password found !!!{reset_color}\r\n'.format(green_color=green,
                                                                                                    reset_color=reset)
                            for dic in password_by_category:
                                try:
                                    buffer += '%s: %s\r\n' % (dic, password_by_category[dic].encode('utf-8'))
                                except Exception:
                                    buffer += '%s: %s\r\n' % (
                                        dic, password_by_category[dic].encode(encoding='utf-8', errors='replace'))
                        buffer += '\r\n'

    except Exception as e:
        print_debug('ERROR', u'Error parsing the json results: {error}'.format(error=e))

    return buffer


def write_in_file(result):
    """
    Write output to file (json and txt files)
    """
    if constant.output in ('json', 'all'):
        try:
            # Human readable Json format
            pretty_json = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
            with open(os.path.join(constant.folder_name, constant.file_name_results + '.json'), 'a+b') as f:
                f.write(pretty_json.encode('UTF-8'))

            constant.st.do_print(u'[+] File written: {file}'.format(
                file=os.path.join(constant.folder_name, constant.file_name_results + '.json'))
            )
        except Exception as e:
            print_debug('ERROR', u'Error writing the output file: {error}'.format(error=e))

    if constant.output in ('txt', 'all'):
        try:
            with open(os.path.join(constant.folder_name, constant.file_name_results + '.txt'), 'a+b') as f:
                a = parse_json_result_to_buffer(result)
                f.write(a.encode("UTF-8"))

            constant.st.write_footer()
            constant.st.do_print(u'[+] File written: {file}'.format(
                file=os.path.join(constant.folder_name, constant.file_name_results + '.txt'))
            )
        except Exception as e:
            print_debug('ERROR', u'Error writing the output file: {error}'.format(error=e))
