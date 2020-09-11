# -*- coding: utf-8 -*- 
# !/usr/bin/python

##############################################################################
#                                                                            #
#                           By Alessandro ZANNI                              #
#                                                                            #
##############################################################################

# Disclaimer: Do Not Use this program for illegal purposes ;)

import argparse
import logging
import sys
import os
import time

# Configuration
from lazagne.config.write_output import write_in_file, StandardOutput
from lazagne.config.manage_modules import get_categories
from lazagne.config.constant import constant
from lazagne.config.run import run_lazagne, create_module_dic


# Object used to manage the output / write functions (cf write_output file)
constant.st = StandardOutput()
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


def manage_advanced_options(user_password=None, dictionary_attack=None):
    if user_password:
        constant.user_password = user_password

    if dictionary_attack:
        constant.dictionary_attack = dictionary_attack


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


def runLaZagne(category_selected='all', subcategories={}, password=None, interactive=False):
    """
    This function will be removed, still there for compatibility with other tools
    Everything is on the config/run.py file
    """
    for pwd_dic in run_lazagne(
            category_selected=category_selected,
            subcategories=subcategories,
            password=password,
            interactive=interactive
    ):
        yield pwd_dic


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
    dic = {'all': {'parents': parents, 'help': 'Run all modules'}}
    for c in categories:
        parser_tab = [PPoptional, categories[c]['parser']]
        if 'subparser' in categories[c]:
            if categories[c]['subparser']:
                parser_tab += categories[c]['subparser']
        parser_tab += [PWrite]
        dic_tmp = {c: {'parents': parser_tab, 'help': 'Run %s module' % c}}
        dic = dict(list(dic.items()) + list(dic_tmp.items()))

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
    manage_advanced_options(user_password=args.get('password', None), dictionary_attack=args.get('attack', None))
    quiet_mode(is_quiet_mode=args['quiet'])

    # Print the title
    constant.st.first_title()

    start_time = time.time()

    category_selected = args['auditType']
    subcategories = clean_args(args)

    for r in runLaZagne(
            category_selected=category_selected,
            subcategories=subcategories,
            password=args.get('password', None),
            interactive=arguments.interactive
    ):
        pass

    write_in_file(constant.stdout_result)
    constant.st.print_footer(elapsed_time=str(time.time() - start_time))
