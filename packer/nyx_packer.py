#!/usr/bin/env python

"""
Copyright (C) 2018 Sergej Schumilo

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

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import uuid
from shutil import copyfile, rmtree, copytree

import common.color
from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC, OKGREEN, BOLD, OKBLUE, INFO_PREFIX, OKGREEN
from common.self_check import self_check
from common.util import ask_for_permission, execute

__author__ = 'sergej'

def copy_dependencies(config, target_executable, target_folder, ld_type, agent_folder, folder=""):
    result_string = ""
    #is_asan_build = False
    asan_lib = None
    ld_linux = None
    download_script = ""
    print(OKGREEN + INFO_PREFIX + "Gathering dependencies of " + target_executable + ENDC)
    cmd = "lddtree -l " + target_executable
    #try:
    proc = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.wait() != 0:
        raise Exception(proc.stderr.read())

    dependencies = proc.stdout.read().decode("utf-8").rstrip().split("\n")

    library_name = []

    libasan_name = "libasan.so"
    ld_linux_name = "ld-linux-x86-64.so"

    for i in range(len(dependencies)):
        if dependencies[i] == "libnyx.so":
            dependencies[i] = agent_folder + "libnyx.so"
            

    i = 1
    for d in dependencies[1:]:
        #print(d)
        if libasan_name in d:
            asan_lib = os.path.basename(d)
            #is_asan_build = True
        if ld_linux_name in d:
            ld_linux = os.path.basename(d)
        download_script += "./hget %s%s %s%s\n"%(folder, os.path.basename(d), folder, os.path.basename(d))
        copyfile(d, "%s/%s"%(target_folder, os.path.basename(d)))

    #except Exception as e:
    #    print(FAIL + "Error while running lddtree: " + str(e) + ENDC)

    return download_script, asan_lib, ld_linux

def check_elf(file):
    proc = subprocess.Popen(("file " + file).split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = proc.stdout.readline()
    proc.wait()

    if not (not b"ELF" in output and not b"executable" in output and not b"Intel" in output):
        if b"32-bit" in output:
            return "32"
        elif b"64-bit" in output:
            return "64"

    print(FAIL + ERROR_PREFIX + "File is not an Intel x86 / x86-64 executable..." + ENDC)
    return None


def check_memlimit(memlimit, mode32):
    if memlimit < 5:
        print(FAIL + ERROR_PREFIX + "Memlimit to low..." + ENDC)
        return False
    if memlimit >= 2048 and mode32:
        print(FAIL + ERROR_PREFIX + "Memlimit to high (x86 mode)..." + ENDC)
        return False
    return True


def checks(config):
    if not os.path.isdir(config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/"):

        if not os.path.isdir(os.path.dirname(os.path.realpath(__file__)) + "/" + config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/"):
            print(FAIL + ERROR_PREFIX + "Wrong path to \"AGENTS-FOLDER\" configured..." + ENDC)
            return False
        else:
            config.config_values["AGENTS-FOLDER"] = os.path.dirname(os.path.realpath(__file__)) + "/" + config.config_values["AGENTS-FOLDER"]
    return True

def is_asan_executable(executable):
    import mmap

    with open(executable) as f:
        s = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        if s.find(b"ASAN_OPTIONS") != -1:
            return True
    return False

def spec_is_compiled(spec_folder_path):
    return os.path.isfile(spec_folder_path + "/nyx_net_spec.msgp") 

def interpreter_path_valid(path):
    return os.path.isdir(path + "/spec_lib")


def compile_spec(spec_folder_path, interpreter_folder_path):
    if not interpreter_path_valid(interpreter_folder_path):
        print(FAIL + "Error: nyx interpreter path is incorrenct (*check nyx.ini*)!" + ENDC)
        return False

    print(OKGREEN + INFO_PREFIX+ "compiling spec (%s) ..."%(spec_folder_path) + ENDC)
    os.environ["NYX_INTERPRETER_BUILD_PATH"] = interpreter_folder_path
    execute(["python3", "nyx_net_spec.py"], spec_folder_path, print_output=True)
    if not spec_is_compiled(spec_folder_path):
        print(FAIL + "Error: spec compile script error!" + ENDC)
        return False
    return True


def compile(config):

    if config.argument_values["spec"]:
        SPEC_FOLDER = os.path.abspath(config.argument_values["spec"])
    else:
        SPEC_FOLDER = None

    if config.argument_values["nyx_net_stdin"]:
        NYX_NET_STDIN = os.path.abspath(config.argument_values["nyx_net_stdin"])
        #print(NYX_NET_STDIN)
    else:
        NYX_NET_STDIN = None

    DELAYED_INIT = config.argument_values["delayed_init"]
    FAST_EXIT_MODE = config.argument_values["fast_reload_mode"]
    LEGACY_FILE_MODE = config.argument_values["file"]
    NET_FUZZ_MODE = config.argument_values["nyx_net"]
    NET_FUZZ_PORT = config.argument_values["nyx_net_port"]
    DISABLE_PT_RANGE_A = config.argument_values["no_pt_auto_conf_a"]
    DISABLE_PT_RANGE_B = config.argument_values["no_pt_auto_conf_b"]
    SETUP_FOLDER = config.argument_values["setup_folder"]
    UDP_MODE = config.argument_values["nyx_net_udp"]
    CLIENT_MODE = config.argument_values["nyx_net_client_mode"]
    DEBUG_MODE = config.argument_values["nyx_net_debug_mode"]
    STDOUT_STDERR_DEBUG = config.argument_values["debug_stdin_stderr"]
    IGNORE_UDP_PORT = config.argument_values["ignore_udp_port"]
    PRE_PROCESS = config.argument_values["add_pre_process"]
    PRE_PROCESS_ARGS = config.argument_values["add_pre_process_args"]
    SET_CLIENT_UDP_PORT = config.argument_values["set_client_udp_port"]

    if config.argument_values["mode"] == "afl":
        LEGACY_MODE = True
    elif config.argument_values["mode"] == "spec":
        LEGACY_MODE = False
    else:
        raise Exception("Unkown mode: %s"%(config.argument_values["mode"]))
    
    if config.argument_values["coverage"] == "instrumentation":
        COVERAGE_MODE = True
    elif config.argument_values["coverage"] == "processor_trace":
        COVERAGE_MODE = False
    else:
        raise Exception("Unkown mode: %s"%(config.argument_values["Coverage"]))
 
    #print(DISABLE_PT_RANGE_A)
    #print(DISABLE_PT_RANGE_B)

    if not LEGACY_MODE and not SPEC_FOLDER:
        print(FAIL + "Error: spec not found!" + ENDC)
        return 

    if not LEGACY_MODE and SPEC_FOLDER:
        if not compile_spec(SPEC_FOLDER, config.config_values["NYX-INTERPRETER-FOLDER"]):
            return

    if len(os.listdir(config.argument_values["output_dir"])) != 0:
        if config.argument_values["purge"]:
            #print(WARNING + "Warning: %s was not empty!"%(config.argument_values["output_dir"]) + ENDC)
            rmtree(config.argument_values["output_dir"])
            os.mkdir(config.argument_values["output_dir"])
        else:
            print(FAIL + "Error: %s is not empty!"%(config.argument_values["output_dir"]) + ENDC)
            return

    target_architecture = check_elf(config.argument_values["binary_file"])
    if not target_architecture:
        return

    if not check_memlimit(config.argument_values["m"], target_architecture == "m32"):
        return

    print(OKGREEN + INFO_PREFIX + "Executable architecture is Intel " + target_architecture + "-bit ..." + ENDC)

    os.environ["STDOUT_STDERR_DEBUG"] = ""
    if SPEC_FOLDER:
        os.environ["NYX_SPEC_FOLDER"] = SPEC_FOLDER + "/build"
    if LEGACY_MODE:
        os.environ["LEGACY_MODE"] = "ON"
    if NET_FUZZ_MODE:
        os.environ["NET_FUZZ"] = "ON"
    if UDP_MODE:
        os.environ["UDP_MODE"] = "-DUDP_MODE "
    if CLIENT_MODE:
        os.environ["CLIENT_MODE"] = "-DCLIENT_MODE "
    if DEBUG_MODE:
        os.environ["DEBUG_MODE"] = "-DDEBUG_MODE "
    if STDOUT_STDERR_DEBUG:
        os.environ["STDOUT_STDERR_DEBUG"] = "-DSTDOUT_STDERR_DEBUG "
    if IGNORE_UDP_PORT:
        os.environ["STDOUT_STDERR_DEBUG"] += "-DIGNORE_PORT=" + str(IGNORE_UDP_PORT) + " "
    if PRE_PROCESS and PRE_PROCESS_ARGS:
        os.environ["STDOUT_STDERR_DEBUG"] += "-DUSE_PRE_PROCESS "
    if SET_CLIENT_UDP_PORT:
        os.environ["STDOUT_STDERR_DEBUG"] += "-DCLIENT_UDP_PORT=" + str(SET_CLIENT_UDP_PORT) + " "

    if target_architecture == "64":
        objcopy_type = "elf64-x86-64"
        mode = "64"
        ld_type = "elf_x86_64"
        agent_folder = config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin64/"
        print(OKGREEN + INFO_PREFIX + "Recompiling..." + ENDC)


        execute(["bash", "compile_64.sh"], config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/",
                    print_output=True)

    else:
        objcopy_type = "elf32-i386"
        mode = "32"
        ld_type = "elf_i386"
        agent_folder = config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/bin32/"
        execute(["bash", "compile_32.sh"], config.config_values["AGENTS-FOLDER"] + "/linux_x86_64-userspace/",
                    print_output=True)

    if SPEC_FOLDER:
        copyfile("%s/%s"%(SPEC_FOLDER, "nyx_net_spec.msgp"), "%s/%s"%(config.argument_values["output_dir"], "spec.msgp"))


    if NYX_NET_STDIN:
        copyfile(NYX_NET_STDIN, "%s/%s"%(config.argument_values["output_dir"], "stdin.input"))


    download_script = "chmod +x hget\n"
    download_script += "cp hget /tmp/\n"
    download_script += "cd /tmp/\n"

    download_script += "echo 0 > /proc/sys/kernel/randomize_va_space\n"
    download_script += "echo 0 > /proc/sys/kernel/printk\n"

    download_script += "./hget hcat hcat\n"
    download_script += "./hget habort habort\n"
    download_script += "chmod +x hcat\n"
    download_script += "chmod +x habort\n"

    download_script += "./hget ld_preload_fuzz.so ld_preload_fuzz.so\n"
    download_script += "chmod +x ld_preload_fuzz.so\n"

    if NYX_NET_STDIN:
        download_script += "./hget stdin.input stdin.input\n"


    if NET_FUZZ_MODE:
        download_script += "ifconfig lo 127.0.0.1 netmask 255.0.0.0 up\n"

    download_script += "echo \"Let's get our dependencies...\" | ./hcat\n"

    if PRE_PROCESS:
        os.mkdir(config.argument_values["output_dir"] + "/pre_process")
        pre_process_dependencies, pre_process_asan_lib, ld_linux = copy_dependencies(config, PRE_PROCESS,  config.argument_values["output_dir"]+"/pre_process", ld_type, agent_folder, folder="pre_process/")

        download_script += "mkdir pre_process/\n"
        download_script += pre_process_dependencies
        
        copyfile(PRE_PROCESS, "%s/%s"%(config.argument_values["output_dir"] + "/pre_process", os.path.basename(PRE_PROCESS)))
        download_script += "./hget pre_process/%s pre_process/pre_process\n"%(os.path.basename(PRE_PROCESS))

    dependencies, asan_lib, ld_linux = copy_dependencies(config, config.argument_values["binary_file"],  config.argument_values["output_dir"], ld_type, agent_folder)

    asan_executable = False
    if not asan_lib:
        asan_executable = is_asan_executable(config.argument_values["binary_file"])

    download_script += dependencies

    download_script += "echo \"Let's get our target executable...\" | ./hcat\n"
    copyfile(config.argument_values["binary_file"], "%s/%s"%(config.argument_values["output_dir"], os.path.basename(config.argument_values["binary_file"])))
    download_script += "./hget %s target_executable\n"%(os.path.basename(config.argument_values["binary_file"]))
    
    if ld_linux:
        download_script += "chmod +x %s\n"%(ld_linux)
    else:
        download_script += "chmod +x target_executable\n"

    if SETUP_FOLDER:
        download_script += "echo \"Let's get our setup script...\" | ./hcat\n"
        download_script += "./hget setup/setup.sh setup.sh\n"
        download_script += ". $PWD/setup.sh\n"
        shutil.copytree(SETUP_FOLDER, "%s/%s"%(config.argument_values["output_dir"], "setup"))  

    hcat_file = agent_folder + "hcat"
    hget_file = agent_folder + "hget"
    habort_file = agent_folder + "habort"

    copyfile(hcat_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(hcat_file)))
    copyfile(hget_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(hget_file)))
    copyfile(habort_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(habort_file)))

    hcat_file = agent_folder + "hcat_no_pt"
    hget_file = agent_folder + "hget_no_pt"
    habort_file = agent_folder + "habort_no_pt"

    copyfile(hcat_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(hcat_file)))
    copyfile(hget_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(hget_file)))
    copyfile(habort_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(habort_file)))

    if LEGACY_MODE:
        ld_preload_fuzz_file = agent_folder + "ld_preload_fuzz.so"
        ld_preload_fuzz_file_legacy = agent_folder + "ld_preload_fuzz_legacy.so"
        copyfile(ld_preload_fuzz_file_legacy, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(ld_preload_fuzz_file)))
        ld_preload_fuzz_file = agent_folder + "ld_preload_fuzz_no_pt.so"
        ld_preload_fuzz_file_legacy = agent_folder + "ld_preload_fuzz_legacy_no_pt.so"
        copyfile(ld_preload_fuzz_file_legacy, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(ld_preload_fuzz_file)))
    else:
        ld_preload_fuzz_file = agent_folder + "ld_preload_fuzz.so"
        copyfile(ld_preload_fuzz_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(ld_preload_fuzz_file)))
        ld_preload_fuzz_file = agent_folder + "ld_preload_fuzz_no_pt.so"
        copyfile(ld_preload_fuzz_file, "%s/%s"%(config.argument_values["output_dir"], os.path.basename(ld_preload_fuzz_file)))
    
    if PRE_PROCESS and PRE_PROCESS_ARGS:
        download_script += "chmod +x pre_process/pre_process\n"
        download_script += "./hget run.sh run.sh\n"

        f_content = "LD_LIBRARY_PATH=/tmp/pre_process "
        f_content += "pre_process/pre_process %s & \n"%(PRE_PROCESS_ARGS)
        f_content += "\n"

        f = open(config.argument_values["output_dir"]+"/run.sh", "w")
        f.write(f_content)
        f.close()

    download_script += "LD_LIBRARY_PATH=/tmp/:$LD_LIBRARY_PATH "

    if asan_lib:
        download_script += "LD_BIND_NOW=1 LD_PRELOAD=/tmp/%s:ld_preload_fuzz.so "%(asan_lib)
    else:
        download_script += "LD_BIND_NOW=1 LD_PRELOAD=/tmp/ld_preload_fuzz.so "
    download_script += "ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:log_path=/tmp/data.log:abort_on_error=true __AFL_DEFER_FORKSRV=1 "

    if DELAYED_INIT:
        download_script += "DELAYED_NYX_FUZZER_INIT=ON "
    if COVERAGE_MODE:
        download_script += "NYX_AFL_PLUS_PLUS_MODE=ON AFL_MAP_SIZE=8388608 "
    if FAST_EXIT_MODE:
        download_script += "NYX_FAST_EXIT_MODE=TRUE "
    if NET_FUZZ_MODE:
        download_script += "NYX_NET_FUZZ_MODE=ON "
    if NET_FUZZ_PORT:
        download_script += "NYX_NET_PORT=%s "%(NET_FUZZ_PORT)
    if LEGACY_FILE_MODE:
        download_script += "NYX_LEGACY_FILE_MODE=%s "%(config.argument_values["file"])
    if not DISABLE_PT_RANGE_A:
        download_script += "NYX_PT_RANGE_AUTO_CONF_A=ON "
    if not DISABLE_PT_RANGE_B:
        download_script += "NYX_PT_RANGE_AUTO_CONF_B=ON "
    if asan_lib or asan_executable:
        download_script += "NYX_ASAN_EXECUTABLE=TRUE "
    else:
        download_script += "MALLOC_CHECK_=2 " 

    if ld_linux:
        download_script += "./%s ./target_executable %s"%(ld_linux, config.argument_values["args"]) # fixme
    else:
        download_script += "./target_executable %s"%(config.argument_values["args"]) # fixme

    if NYX_NET_STDIN:
        download_script += " < stdin.input "
    else:
        download_script += " "

    if STDOUT_STDERR_DEBUG:
        download_script += " > stdout.txt 2> stderr.txt\n"
        download_script += "cat stdout.txt | ./hcat\n"
        download_script += "cat stderr.txt | ./hcat\n"
    else:
        download_script += " > /dev/null 2> /dev/null\n"

 
    download_script += "dmesg | grep segfault | ./hcat\n"
    download_script += "./habort \"Target has terminated without initializing the fuzzing agent ...\"\n"

    # Todo: ASAN, memlimit, stdin, filemode ...

    f = open("%s/fuzz.sh"%(config.argument_values["output_dir"]), "w")
    f.write(download_script)
    f.close()

    f = open("%s/fuzz_no_pt.sh"%(config.argument_values["output_dir"]), "w")
    f.write(download_script.replace("./hget hcat", "./hget hcat_no_pt").replace("./hget habort", "./hget habort_no_pt").replace("./hget ld_preload_fuzz.so", "./hget ld_preload_fuzz_no_pt.so"))
    f.close()

    print(OKGREEN + INFO_PREFIX + "NYX share-dir is ready -> %s"%(config.argument_values["output_dir"]))

    return

def main():
    from common.config import PackerConfiguration
    config = PackerConfiguration()

    if not self_check():
        return 1

    if not checks(config):
        return False

    compile(config)


if __name__ == "__main__":
    main()