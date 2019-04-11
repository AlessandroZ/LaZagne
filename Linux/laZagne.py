#!/usr/bin/env python
# -*- encoding: utf-8 -*-

##############################################################################
#                                                                            #
#                           By Alessandro ZANNI                              #
#                                                                            #
##############################################################################

# Disclaimer: Do Not Use this program for illegal purposes ;)

import sys
import os
import argparse
import logging

from lazagne.config.write_output import write_in_file, StandardOutput
from lazagne.config.manage_modules import get_categories
from lazagne.config.constant import constant
from lazagne.config.run import create_module_dic, run_lazagne

import time

constant.st = StandardOutput()  # Object used to manage the output / write functions (cf write_output file)
modules = create_module_dic()


def output(output_dir=None, txt_format=False, json_format=False, all_format=False):
    if output_dir:
        if os.path.isdir(output_dir):
            constant.folder_name = output_dir
        else:
            print('[!] Specify a directory, not a file !')

    if txt_format:
        constant.output = 'txt'

    if json_format:
        constant.output = 'json'

    if all_format:
        constant.output = 'all'

    if constant.output:
        if not os.path.exists(constant.folder_name):
            os.makedirs(constant.folder_name)
            # constant.file_name_results = 'credentials' # let the choice of the name to the user

        if constant.output != 'json':
            constant.st.write_header()


def quiet_mode(is_quiet_mode=False):
    if is_quiet_mode:
        constant.quiet_mode = True


def verbosity(verbose=0):
    # Write on the console + debug file
    if verbose == 0:
        level = logging.CRITICAL
    elif verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
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


def clean_args(arg):
    """
    Remove not necessary values to get only subcategories
    """
    for i in ['output', 'write_normal', 'write_json', 'write_all', 'verbose', 'auditType', 'quiet']:
        try:
            del arg[i]
        except Exception:
            pass
    return arg


def runLaZagne(category_selected='all', subcategories={}):
    """
    This function will be removed, still there for compatibility with other tools
    Everything is on the config/run.py file
    """
    for pwd_dic in run_lazagne(category_selected=category_selected, subcategories=subcategories):
        yield pwd_dic


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description=constant.st.banner, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--version', action='version', version='Version ' + str(constant.CURRENT_VERSION),
                        help='laZagne version')

    # ------------------------------------------- Permanent options -------------------------------------------
    # Version and verbosity
    PPoptional = argparse.ArgumentParser(
        add_help=False,
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.max_help))
    PPoptional._optionals.title = 'optional arguments'
    PPoptional.add_argument('-v', dest='verbose', action='count', default=0, help='increase verbosity level')
    PPoptional.add_argument('-quiet', dest='quiet', action='store_true', default=False,
                            help='quiet mode: nothing is printed to the output')

    # Output
    PWrite = argparse.ArgumentParser(
        add_help=False,
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.max_help)
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
            formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=constant.max_help))
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
                            max_help_position=constant.max_help
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
    dic = {'all': {'parents': parents, 'help': 'Run all modules'}}
    for c in all_categories:
        parser_tab = [PPoptional, all_categories[c]['parser']]
        if 'subparser' in all_categories[c]:
            if all_categories[c]['subparser']:
                parser_tab += all_categories[c]['subparser']
        parser_tab += [PWrite]
        dic_tmp = {c: {'parents': parser_tab, 'help': 'Run %s module' % c}}
        dic.update(dic_tmp)

    # 2- Main commands
    subparsers = parser.add_subparsers(help='Choose a main command')
    for d in dic:
        subparsers.add_parser(d, parents=dic[d]['parents'], help=dic[d]['help']).set_defaults(auditType=d)

    # ------------------------------------------- Parse arguments -------------------------------------------

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = dict(parser.parse_args()._get_kwargs())
    arguments = parser.parse_args()

    # Define constant variables
    output(
        output_dir=args['output'],
        txt_format=args['write_normal'],
        json_format=args['write_json'],
        all_format=args['write_all']
    )
    verbosity(verbose=args['verbose'])
    quiet_mode(is_quiet_mode=args['quiet'])

    # Print the title
    constant.st.first_title()

    start_time = time.time()

    category = args['auditType']
    subcategories = clean_args(args)

    for run in runLaZagne(category, subcategories):
        pass

    write_in_file(constant.stdout_result)
    constant.st.print_footer(elapsed_time=str(time.time() - start_time))
