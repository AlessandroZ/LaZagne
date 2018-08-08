#!/usr/bin/env python
# -*- encoding: utf-8 -*-

##############################################################################
#                                                                            #
#                           By Alessandro ZANNI                              #
#                                                                            #
##############################################################################

# Disclaimer: Do Not Use this program for illegal purposes ;)

import json
import sys
import os
import traceback
import argparse
import logging
import getpass

from lazagne.config.write_output import parse_json_result_to_buffer, print_debug, StandardOutput
from lazagne.config.manage_modules import get_categories, get_modules
from lazagne.config.constant import *

import time

# Object used to manage the output / write functions (cf write_output file)
constant.st = StandardOutput()

# Tab containing all passwords
stdoutRes = []
modules = {}

# Define a dictionary for all modules
for c in get_categories():
    modules[c] = {}

# Add all modules to the dictionary
for m in get_modules():
    modules[m.category][m.options['dest']] = m


def output():
    if args['output']:
        if os.path.isdir(args['output']):
            constant.folder_name = args['output']
        else:
            print('[!] Specify a directory, not a file !')

    if args['write_normal']:
        constant.output = 'txt'

    if args['write_json']:
        constant.output = 'json'

    if args['write_all']:
        constant.output = 'all'

    if constant.output:
        if not os.path.exists(constant.folder_name):
            os.makedirs(constant.folder_name)
        # constant.file_name_results = 'credentials' # let the choice of the name to the user

        if constant.output != 'json':
            constant.st.write_header()


def quiet_mode():
    if args['quiet']:
        constant.quiet_mode = True


def verbosity():
    # Write on the console + debug file
    level = None
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
            constant.st.title_info(i.capitalize())  # Print title
            pwd_found = module[i].run()  # Run the module
            constant.st.print_output(i.capitalize(), pwd_found)  # Print the results

            # Return value - not used but needed
            yield True, i.capitalize(), pwd_found
        except Exception:
            error_message = traceback.format_exc()
            print_debug('DEBUG', error_message)
            yield False, i.capitalize(), error_message


# Run module
def run_module(category_selected):
    categories = [category_selected] if category_selected != 'all' else get_categories()
    for cat in categories:
        for r in launch_module(modules[cat]):
            yield r


# Write output to file (json and txt files)
def write_in_file(result):
    if constant.output == 'json' or constant.output == 'all':
        try:
            # Human readable Json format
            pretty_json = json.dumps(result, sort_keys=True, indent=4, separators=(',', ': '))
            with open(os.path.join(constant.folder_name, constant.file_name_results + '.json'), 'a+b') as f:
                f.write(pretty_json.decode('unicode-escape').encode('UTF-8'))

            constant.st.do_print(u'[+] File written: {file}'.format(
                file=os.path.join(constant.folder_name, constant.file_name_results + '.json'))
            )
        except Exception as e:
            print_debug('ERROR', u'Error writing the output file: {error}'.format(error=e))

    if constant.output == 'txt' or constant.output == 'all':
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


def runLaZagne(category_selected='all'):
    user = getpass.getuser()
    constant.finalResults = {'User': user}

    for r in run_module(category_selected):
        yield r

    stdoutRes.append(constant.finalResults)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description=constant.st.banner, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--version', action='version', version='Version ' + str(constant.CURRENT_VERSION),
                        help='laZagne version')

    # ------------------------------------------- Permanent options -------------------------------------------
    # Version and verbosity
    PPoptional = argparse.ArgumentParser(
        add_help=False,
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
    PPoptional._optionals.title = 'optional arguments'
    PPoptional.add_argument('-v', dest='verbose', action='count', default=0, help='increase verbosity level')
    PPoptional.add_argument('-quiet', dest='quiet', action='store_true', default=False,
                            help='quiet mode: nothing is printed to the output')

    # Output
    PWrite = argparse.ArgumentParser(
        add_help=False,
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION)
    )
    PWrite._optionals.title = 'Output'
    PWrite.add_argument('-oN', dest='write_normal', action='store_true', default=None,
                        help='output file in a readable format')
    PWrite.add_argument('-oJ', dest='write_json', action='store_true', default=None,
                        help='output file in a json format')
    PWrite.add_argument('-oA', dest='write_all', action='store_true', default=None, help='output file in all format')
    PWrite.add_argument('-output', dest='output', action='store', default='.',
                        help='destination path to store results (default:.)')

    # -------------------------------- Add options and suboptions to all modules ------------------------
    all_subparser = []
    all_categories = get_categories()

    for c in all_categories:
        all_categories[c]['parser'] = argparse.ArgumentParser(
            add_help=False,
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.MAX_HELP_POSITION))
        all_categories[c]['parser']._optionals.title = all_categories[c]['help']

        # Manage options
        all_categories[c]['subparser'] = []
        for module in modules[c]:
            m = modules[c][module]
            all_categories[c]['parser'].add_argument(m.options['command'], action=m.options['action'],
                                                 dest=m.options['dest'], help=m.options['help'])

            # Manage all sub options by modules
            if m.suboptions:
                tmp = []
                for sub in m.suboptions:
                    tmp_subparser = argparse.ArgumentParser(
                        add_help=False,
                        formatter_class=lambda prog: argparse.HelpFormatter(
                            prog,
                            max_help_position=constant.MAX_HELP_POSITION
                        )
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
                    all_categories[c]['subparser'] += tmp

    # ------------------------------------------- Print all -------------------------------------------
    parents = [PPoptional] + all_subparser + [PWrite]
    dic = {'all': {'parents': parents, 'help': 'Run all modules', 'func': run_module}}
    for c in all_categories:
        parser_tab = [PPoptional, all_categories[c]['parser']]
        if 'subparser' in all_categories[c]:
            if all_categories[c]['subparser']:
                parser_tab += all_categories[c]['subparser']
        parser_tab += [PWrite]
        dic_tmp = {c: {'parents': parser_tab, 'help': 'Run %s module' % c, 'func': run_module}}
        dic.update(dic_tmp)

    # 2- Main commands
    subparsers = parser.add_subparsers(help='Choose a main command')
    for d in dic:
        subparsers.add_parser(d, parents=dic[d]['parents'], help=dic[d]['help']).set_defaults(func=dic[d]['func'],
                                                                                              auditType=d)

    # ------------------------------------------- Parse arguments -------------------------------------------

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = dict(parser.parse_args()._get_kwargs())
    arguments = parser.parse_args()
    category = args['auditType']

    quiet_mode()

    # Print the title
    constant.st.first_title()

    # Define constant variables
    output()
    verbosity()

    start_time = time.time()

    for run in runLaZagne(category):
        pass

    write_in_file(stdoutRes)
    constant.st.print_footer(elapsed_time=str(time.time() - start_time))
