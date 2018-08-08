# -*- coding: utf-8 -*-
from time import gmtime, strftime
import getpass
import logging
import ctypes
import socket
import os
import sys

from .constant import constant

# --------------------------- Standard output functions ---------------------------

STD_OUTPUT_HANDLE = -11
std_out_handle = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
tmp_user = None


class StandartOutput():
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

        self.FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])

    def set_color(self, color='white', intensity=False):
        c = None
        if color == 'white':
            c = 0x07
        elif color == 'red':
            c = 0x04
        elif color == 'green':
            c = 0x02
        elif color == 'cyan':
            c = 0x03

        if intensity:
            c = c | 0x08

        ctypes.windll.kernel32.SetConsoleTextAttribute(std_out_handle, c)

    # print banner
    def first_title(self):
        self.do_print(message=self.banner, color='white', intensity=True)

    # info option for the logging
    def print_title(self, title):
        t = u'------------------- ' + title + ' passwords -----------------\n'
        self.do_print(message=t, color='white', intensity=True)

    # debug option for the logging
    def title_info(self, title):
        t = u'------------------- ' + title + ' passwords -----------------\n'
        self.print_logging(function=logging.info, prefix='', message=t, color='white', intensity=True)

    def print_user(self, user):
        self.do_print(u'########## User: {user} ##########\n'.format(user=user))

    def print_footer(self, elapsed_time=None):
        footer = '\n[+] %s passwords have been found.\n' % str(constant.nbPasswordFound)
        if not logging.getLogger().isEnabledFor(logging.INFO):
            footer += 'For more information launch it again with the -v option\n'
        if elapsed_time:
            footer += '\nelapsed time = ' + str(elapsed_time)
        self.do_print(footer)

    def print_hex(self, src, length=8):
        N = 0
        result = ''
        while src:
            s, src = src[:length], src[length:]
            hexa = ' '.join(["%02X" % ord(x) for x in s])
            s = s.translate(self.FILTER)
            result += "%04X   %-*s   %s\n" % (N, length * 3, hexa, s)
            N += length
        return result

    def try_unicode(self, obj, encoding='utf-8'):
        try:
            if isinstance(obj, basestring):
                if not isinstance(obj, unicode):
                    obj = unicode(obj, encoding)
        except UnicodeEncodeError:
            pass
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
            print message.encode('cp850')
        except Exception as e:
            print_debug('ERROR', u'error encoding: {error}'.format(error=e))
            try:
                print(message)
            except Exception:
                print repr(message)

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
        # Quiet mode => nothing is printed
        if constant.quiet_mode:
            return

        # manage differently hashes / and hex value
        if pwd_found:
            category = None
            if '__LSASecrets__' in pwd_found:
                pwd_found.remove('__LSASecrets__')
                category = 'lsa'
                pwd_found = pwd_found[0]
            elif '__Hashdump__' in pwd_found:
                pwd_found.remove('__Hashdump__')
                category = 'hash'
                pwd_found = pwd_found[0]
            elif '__MSCache__' in pwd_found:
                pwd_found.remove('__MSCache__')
                category = 'mscache'
                pwd_found = pwd_found[0]

        if pwd_found:

            # if the debug logging level is not apply => print the title
            if not logging.getLogger().isEnabledFor(logging.INFO):
                # print the username only if password have been found
                user = constant.finalResults.get('User', '')
                global tmp_user
                if user != tmp_user:
                    tmp_user = user
                    self.print_user(user)

                # if not title1:
                self.print_title(software_name)

            to_write = []

            # LSA Secrets will not be written on the output file
            if category == 'lsa':
                for k in pwd_found:
                    hex = self.print_hex(pwd_found[k], length=16)
                    to_write.append([k, hex])
                    self.do_print(k)
                    self.do_print(hex)
                self.do_print()

            # Windows Hashes
            elif category == 'hash':
                for pwd in pwd_found:
                    self.do_print(pwd)
                    to_write.append(pwd)
                self.do_print()

            # Windows MSCache
            elif category == 'mscache':
                for pwd in pwd_found:
                    self.do_print(pwd)
                    to_write.append(pwd)
                self.do_print()

            # Other passwords
            else:
                # Remove duplicated password
                pwd_found = [dict(t) for t in set([tuple(d.items()) for d in pwd_found])]

                for pwd in pwd_found:
                    password_category = False
                    # Detect which kinds of password has been found
                    lower_list = [s.lower() for s in pwd.keys()]
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

                    # Do not print empty passwords
                    try:
                        if not pwd[password_category[0].capitalize()]:
                            continue
                    except Exception:
                        pass

                    # No password found
                    if not password_category:
                        print_debug("FAILED", u'Password not found !!!')
                    else:
                        # Store all passwords found on a table => for dictionary attack if master password set
                        constant.nbPasswordFound += 1
                        passwd = None
                        try:
                            passwd = unicode(pwd[password_category[
                                0].capitalize()])  # unicode shoud be removed for Python 3 compatibility
                            if passwd and passwd not in constant.passwordFound:
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

                    for p in pwd.keys():
                        self.do_print('%s: %s' % (p, pwd[p]))
                    self.do_print()

            # write credentials into a text file
            self.checks_write(to_write, software_name)
        else:
            logging.info('[!] No passwords found\n')

    def write_header(self):
        time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
        header = u'{banner}\r\n- Date: {date}\r\n- Username: {username}\r\n- Hostname:{hostname}\r\n\r\n'.format(
            banner=self.banner.replace('\n', '\r\n'),
            date=str(time),
            username=getpass.getuser().decode(sys.getfilesystemencoding()),
            hostname=socket.gethostname().decode(sys.getfilesystemencoding())
        )
        with open(os.path.join(constant.folder_name, '{}.txt'.format(constant.file_name_results)), "a+b") as f:
            f.write(header.encode("UTF-8"))

    def write_footer(self):
        footer = '\n[+] %s passwords have been found.\r\n\r\n' % str(constant.nbPasswordFound)
        open(os.path.join(constant.folder_name, '%s.txt' % constant.file_name_results), "a+b").write(footer)

    def checks_write(self, values, category):
        if values:
            if "Passwords" not in constant.finalResults:
                constant.finalResults["Passwords"] = []
            constant.finalResults["Passwords"].append([{"Category": category}, values])


def print_debug(error_level, message):
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

def parse_json_result_to_buffer(jsonString, color=False):
    buffer = u''
    try:
        for json in jsonString:
            if json:
                buffer += u'##################  User: {username} ################## \r\n'.format(username=json['User'])
                if 'Passwords' not in json:
                    buffer += u'No passwords found for this user !\r\n\r\n'
                else:
                    for all_passwords in json['Passwords']:
                        buffer += u'\r\n------------------- {password_category} -----------------\r\n'.format(
                            password_category=all_passwords[0]['Category'])
                        if all_passwords[0]['Category'].lower() in ['lsa', 'hashdump', 'cachedump']:
                            for dic in all_passwords[1]:
                                if all_passwords[0]['Category'].lower() == 'lsa':
                                    for d in dic:
                                        buffer += u'%s\r\n' % (constant.st.try_unicode(d))
                                else:
                                    buffer += u'%s\r\n' % (constant.st.try_unicode(dic))
                        else:
                            for password_by_category in all_passwords[1]:
                                buffer += u'\r\nPassword found !!!\r\n'
                                for dic in password_by_category.keys():
                                    try:
                                        buffer += u'%s: %s\r\n' % (
                                        dic, constant.st.try_unicode(password_by_category[dic]))
                                    except Exception as e:
                                        print_debug(u'ERROR', u'Error retrieving the password encoding: %s' % e)
                        buffer += u'\r\n'
    except Exception as e:
        print_debug('ERROR', u'Error parsing the json results: {error}'.format(error=e))

    return buffer
