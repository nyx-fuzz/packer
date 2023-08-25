"""
Copyright (C) 2017 Sergej Schumilo

This file is part of kAFL Fuzzer (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.
"""

import configparser


import argparse
import json
import os
import re
import sys
import common.color
from common.info import show_banner

from common.util import is_float, is_int, Singleton, execute, to_real_path
from common.self_check import vmx_pt_get_addrn
from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC, OKGREEN, BOLD, OKBLUE, INFO_PREFIX, OKGREEN

default_section = "Packer"
default_config = {
                  "AGENTS-FOLDER": "./",
                  "NYX-INTERPRETER-FOLDER": "./interpreter/",
                  "QEMU-PT_PATH": "../../QEMU-Nyx/x86_64-softmmu/qemu-system-x86_64",
                  "KERNEL": "../linux_initramfs/bzImage-linux-4.15-rc7",
                  "INIT_RAMFS": "../linux_initramfs/init.cpio.gz",
                  "DEFAULT_FUZZER_CONFIG_FOLDER": "./fuzzer_configs/",
                  "DEFAULT_VM_HDA": "",
                  "DEFAULT_VM_PRESNAPSHOT": "",
                  }


class ArgsParser(argparse.ArgumentParser):

    banner_text = None

    def set_banner_text(self, banner_text):
        self.banner_text = banner_text

    def error(self, message):
        show_banner(self.banner_text)
        self.print_help()
        print('\033[91m[Error] %s\n\n\033[0m\n' % message)
        
        sys.exit(1)


def create_dir(dirname):
    if not os.path.isdir(dirname):
        try:
            os.makedirs(dirname)
        except:
            msg = "Cannot create directory: {0}".format(dirname)
            raise argparse.ArgumentTypeError(msg)
    return dirname


def parse_is_dir(dirname):
    if not os.path.isdir(dirname):
        msg = "{0} is not a directory".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname


def parse_is_setup_dir(dirname):
    if dirname == "":
        return None
    if not os.path.isdir(dirname):
        msg = "{0} is not a directory".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    elif not os.path.isfile(dirname+"/setup.sh"):
        msg = "{0}/setup.sh not found".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname

def parse_is_file(dirname):
    if not os.path.isfile(dirname):
        msg = "{0} is not a file".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname

def parse_is_file_or_dir(dirname):
    if not (os.path.isfile(dirname) or os.path.isdir(dirname)):
        msg = "{0} is not a file".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname


def parse_ignore_range(string):
    m = re.match(r"(\d+)(?:-(\d+))?$", string)
    if not m:
        raise argparse.ArgumentTypeError("'" + string + "' is not a range of number.")
    start = min(int(m.group(1)), int(m.group(2)))
    end = max(int(m.group(1)), int(m.group(2))) or start
    if end > (128 << 10):
        raise argparse.ArgumentTypeError("Value out of range (max 128KB).")

    if start == 0 and end == (128 << 10):
        raise argparse.ArgumentTypeError("Invalid range specified.")
    return list([start, end])


def parse_range_ip_filter(string):
    m = re.match(r"([(0-9abcdef]{1,16})(?:-([0-9abcdef]{1,16}))?$", string.replace("0x", "").lower())
    if not m:
        raise argparse.ArgumentTypeError("'" + string + "' is not a range of number.")

    # print(m.group(1))
    # print(m.group(2))
    start = min(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16))
    end = max(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16)) or start

    if start > end:
        raise argparse.ArgumentTypeError("Invalid range specified.")
    return list([start, end])


class FullPath(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))


class MapFullPaths(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, map(lambda p: os.path.abspath(os.path.expanduser(p)), values))


class ConfigReader(object):

    def __init_config(self, config_file):    
        if not os.path.exists(config_file):
            print("Configuration \"%s\" not found -> Creating..."%(os.path.realpath(config_file)))
            f = open(config_file, "w")
            config = configparser.ConfigParser()
            config["Packer"] = {}
            for k, v in self.default_values.items():
                config["Packer"][k] = v
            config.write(f)
            f.close()

    def __get_path(self, value):
        if self.config_value[value].startswith("."):
            self.config_value[value] = to_real_path(self.config_value[value])           
        return self.config_value[value]


    def __self_check(self):

        if not os.path.isfile(self.__get_path('QEMU-PT_PATH')):
            print("nyx.ini ERROR: %s is not a file (fix %s)"%(self.config_value['QEMU-PT_PATH'], "QEMU-PT_PATH"))
            sys.exit(1)

        if not os.path.isdir(self.__get_path('NYX-INTERPRETER-FOLDER')):
            print("nyx.ini ERROR: %s is not a folder (fix %s)"%(self.config_value['NYX-INTERPRETER-FOLDER'], "NYX-INTERPRETER-FOLDER"))
            sys.exit(1)

        if not os.path.isfile(self.__get_path("INIT_RAMFS")):
            if self.__get_path('INIT_RAMFS') == to_real_path(default_config['INIT_RAMFS']):
                print(OKGREEN + INFO_PREFIX+ "Packing init_ramfs..." + ENDC)
                execute(["sh", "pack.sh"], to_real_path("../linux_initramfs/"), print_output=True)

        if not os.path.isfile(self.__get_path('KERNEL')):
            print("nyx.ini ERROR: %s is not a file (fix %s)"%(self.config_value['KERNEL'], "KERNEL"))
            sys.exit(1)

        if not os.path.isfile(self.__get_path("INIT_RAMFS")):
            print("nyx.ini ERROR: %s is not a file (fix %s)"%(self.config_value['INIT_RAMFS'], "INIT_RAMFS"))
            sys.exit(1)

        if not os.path.isdir(self.__get_path('DEFAULT_FUZZER_CONFIG_FOLDER')):
            print("nyx.ini ERROR: %s is not a folder (fix %s)"%(self.config_value['DEFAULT_FUZZER_CONFIG_FOLDER'], "DEFAULT_FUZZER_CONFIG_FOLDER"))
            sys.exit(1)

        # optional
        if self.config_value['DEFAULT_VM_HDA'] != "" and not os.path.isfile(self.__get_path("DEFAULT_VM_HDA")):
            print("nyx.ini ERROR: %s is not a file (fix %s)"%(self.config_value['DEFAULT_VM_HDA'], "DEFAULT_VM_HDA"))
            sys.exit(1)

        if self.config_value['DEFAULT_VM_PRESNAPSHOT'] != "" and not os.path.isdir(self.__get_path("DEFAULT_VM_PRESNAPSHOT")):
            print("nyx.ini ERROR: %s is not a folder (fix %s)"%(self.config_value['DEFAULT_VM_PRESNAPSHOT'], "DEFAULT_VM_PRESNAPSHOT"))
            sys.exit(1)


    def __init__(self, config_file, section, default_values):
        self.section = section
        self.default_values = default_values
        self.config = configparser.ConfigParser()
        if config_file:
            self.__init_config(config_file)
            self.config.read(config_file)
        else:
            raise Exception("No config file specified (%s)"%(config_file))

        self.config_value = {}
        self.__set_config_values()
        self.__self_check()

    def __set_config_values(self):
        for default_value in self.default_values.keys():
            if self.config.has_option(self.section, default_value):
                try:
                    self.config_value[default_value] = int(self.config.get(self.section, default_value))
                except ValueError:
                    if self.config.get(self.section, default_value) == "True":
                        self.config_value[default_value] = True
                    elif self.config.get(self.section, default_value) == "False":
                        self.config_value[default_value] = False
                    elif self.config.get(self.section, default_value).startswith("[") and \
                            self.config.get(self.section, default_value).endswith("]"):
                        self.config_value[default_value] = \
                            self.config.get(self.section, default_value)[1:-1].replace(' ', '').split(',')
                    elif self.config.get(self.section, default_value).startswith("{") and \
                            self.config.get(self.section, default_value).endswith("}"):
                        self.config_value[default_value] = json.loads(self.config.get(self.section, default_value))
                    else:
                        if is_float(self.config.get(self.section, default_value)):
                            self.config_value[default_value] = float(self.config.get(self.section, default_value))
                        elif is_int(self.config.get(self.section, default_value)):
                            self.config_value[default_value] = int(self.config.get(self.section, default_value))
                        else:
                            self.config_value[default_value] = self.config.get(self.section, default_value)
            else:
                self.config_value[default_value] = self.default_values[default_value]

    def get_values(self):
        return self.config_value


class PackerConfiguration:
    __metaclass__ = Singleton
    global default_section, default_config

    __config_section = default_section
    __config_default = default_config

    def __init__(self, initial=True):
        if initial:
            self.argument_values = None
            self.config_values = None
            self.__load_config()
            self.__load_arguments()
            self.load_old_state = False

    def __load_config(self):
        self.config_values = ConfigReader(os.path.dirname(os.path.realpath(__file__))+"/../nyx.ini", self.__config_section, self.__config_default).get_values()

    def __load_arguments(self):
        modes = ["afl", "spec"]
        modes_help = 'afl\t\t - pack target for an AFL-like fuzzer (such as AFL++, kAFL, Nautilus)\n' \
                     'spec\t\t - pack target for a spec fuzzer (such as Nyx\'s spec-fuzzer)\n'

        coverage_modes = ["instrumentation", "processor_trace"]
        coverage_modes_help = 'instrumentation\t - use compile-time instrumentation (target has to be compiled with an proper compiler)\n' \
                     'processor_trace\t - enable Intel-PT tracing (requires KVM-Nyx)\n'

        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter)
        parser.set_banner_text("Nyx Share Dir Packer")

        parser.add_argument('binary_file', metavar='<Executable>', action=FullPath, type=parse_is_file,
                            help='path to the user space executable file.')
        parser.add_argument('output_dir', metavar='<Output Directory>', action=FullPath, type=create_dir,
                            help='path to the output directory.')
        parser.add_argument('mode', metavar='<Mode>', choices=modes, help=modes_help)
        parser.add_argument('coverage', metavar='<Coverage>', choices=coverage_modes, help=coverage_modes_help)

        parser.add_argument('-args', metavar='<args>', help='define target arguments.', default="", type=str)
        parser.add_argument('-file', metavar='<file>', help='write payload to file instead of stdin.', default="",
                            type=str)
        
        parser.add_argument('-m', metavar='<memlimit>', help='set memory limit [MB] (default 50 MB).', default=50,
                            type=int)
        parser.add_argument('-spec', action=FullPath, type=parse_is_dir, help='path to the NYX spec folder.')

        parser.add_argument('--delayed_init', help='delayed fuzzing entry point', action='store_true', default=False)
        parser.add_argument('--fast_reload_mode', help='fast reload acceleration (experimental)', action='store_true', default=False)
        parser.add_argument('--setup_folder', help='pack addional setup folder', default="", type=parse_is_setup_dir)
        parser.add_argument('--purge', help='delete output_dir', action='store_true', default=False)

        tracing = parser.add_argument_group("Intel-PT Option")

        tracing.add_argument('--no_pt_auto_conf_a', help='disable Intel PT range auto configuration for range A (usually the target executable without shared libraries)', action='store_true', default=False)
        tracing.add_argument('--no_pt_auto_conf_b', help='disable Intel PT range auto configuration for range B (usually all shared libraries without the target executable)', action='store_true', default=False)


        nyx_net_group = parser.add_argument_group("Nyx-Net Option")

        nyx_net_group.add_argument('--nyx_net', help='enable nyx network fuzzing', action='store_true', default=False)
        nyx_net_group.add_argument('--nyx_net_port', metavar='<nyx_net_port>', help='fuzz specified network port', default=0, type=int)
        nyx_net_group.add_argument('--nyx_net_udp', help='fuzz UDP port instead TCP', action='store_true', default=False)
        nyx_net_group.add_argument('--nyx_net_client_mode', help='fuzz target in client mode', action='store_true', default=False)
        nyx_net_group.add_argument('--nyx_net_stdin', help='use file as stdin input', action=FullPath, type=parse_is_file)

        nyx_net_group = parser.add_argument_group("Nyx-Net Advanced Options")
        nyx_net_group.add_argument('--add_pre_process', metavar='<pre_process>', help='path to pre-process', action=FullPath, type=parse_is_file)
        nyx_net_group.add_argument('--add_pre_process_args', metavar='<pre_process_ags>', help='args of preprocess', default="", type=str)
        nyx_net_group.add_argument('--ignore_udp_port', metavar='<ignore_udp_port>', help='ignore specific UDP port', default=0, type=int)
        nyx_net_group.add_argument('--set_client_udp_port', metavar='<set_client_udp_port>', help='set UDP client port number', default=0, type=int)

        debug_group = parser.add_argument_group("Debug Options")

        debug_group.add_argument('--debug_stdin_stderr', help='redirect stdin / stderr data via hcat to hypervisor', action='store_true', default=False)
        debug_group.add_argument('--nyx_net_debug_mode', help='add hprintfs to debug nyx_net targets', action='store_true', default=False)


        self.argument_values = vars(parser.parse_args())

class ConfigGeneratorConfiguration:
    __metaclass__ = Singleton
    global default_section, default_config

    __config_section = default_section
    __config_default = default_config

    def __init__(self, initial=True):
        if initial:
            self.argument_values = None
            self.config_values = None
            self.__load_config()
            self.__load_arguments()
            self.load_old_state = False

    def __load_config(self):
        self.config_values = ConfigReader(os.path.dirname(os.path.realpath(__file__)) +"/../nyx.ini", self.__config_section, self.__config_default).get_values()

    def __load_arguments(self):

        parser = ArgsParser(formatter_class=argparse.RawTextHelpFormatter)

        parser.set_banner_text("Nyx Config Generator")

        modes = ["Kernel", "Snapshot"]
        modes_help = 'Kernel\tuse defaults for initramfs kernel VM\n' \
                     'Snapshot\tuse defaults for full VM with snapshots\n'

        parser.add_argument('share_dir', metavar='<Share Directory>', action=FullPath, type=parse_is_dir, help='path to the share directory.')
        parser.add_argument('vm_type', metavar='<VM Type>', choices=modes, help=modes_help)

        parser.add_argument('-m', metavar='<memory>', help='set memory of target VM', default=512, type=int)
        parser.add_argument('-w', metavar='<workdir>', help='path to wordir', type=str)
        parser.add_argument('-d', metavar='<dictionary>', help='path to dictonary', type=parse_is_file)
        parser.add_argument('-s', metavar='<seeds>', help='path to seeds', type=parse_is_dir)

        parser.add_argument('-n', metavar='<nano_sec>', help='timeout threshold option (nono-seconds)', type=int)

        parser.add_argument('--disable_timeouts', help='disable timeout detection', action='store_true', default=False)
        parser.add_argument('--path_to_default_config', help='overwrite path to default config', type=str)

        self.argument_values = vars(parser.parse_args())

