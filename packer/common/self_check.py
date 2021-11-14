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

import os
import subprocess
import sys
from fcntl import ioctl

import common.color
from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC


def check_if_nativ_lib_compiled():
    if not (os.path.exists(os.path.dirname(sys.argv[0])+"/fuzzer/native/") and os.path.exists("os.path.dirname(sys.argv[0])+"/"fuzzer/native/bitmap.so")) and not (os.path.exists("fuzzer/native/") and os.path.exists("fuzzer/native/bitmap.so")):
        print(WARNING + WARNING_PREFIX + "bitmap.so file does not exist. Compiling..." + ENDC)

        current_dir = os.getcwd()
        os.chdir( os.path.dirname(sys.argv[0]) )
        p = subprocess.Popen(("gcc fuzzer/native/bitmap.c --shared -fPIC -O3 -o fuzzer/native/bitmap.so").split(" "),
                             stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.wait() != 0:
            print(FAIL + ERROR_PREFIX + "Compiling failed..." + ENDC)
        os.chdir( current_dir )
        return False
    return True


def check_if_installed(cmd):
    p = subprocess.Popen(("which " + cmd).split(" "), stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    if p.wait() != 0:
        return False

    try:
        import msgpack
    except ImportError:
        print(FAIL + ERROR_PREFIX + "Package 'msgpack' is missing (Hint: `pip install msgpack`)!" + ENDC)
        return False

    return True


def check_version():
    if sys.version_info < (3, 0, 0):
        print(FAIL + ERROR_PREFIX + "This script requires python 3.0 or higher!" + ENDC)
        return False
    return True


def check_packages():
    if not check_if_installed("lddtree"):
        print(FAIL + ERROR_PREFIX + "Tool 'lddtree' is missing (Hint: run `sudo apt install pax-utils`)!" + ENDC)
        return False
    return True


def vmx_pt_get_addrn(verbose=True):
    from fcntl import ioctl

    KVMIO = 0xAE
    KVM_VMX_PT_GET_ADDRN = KVMIO << (8) | 0xe9

    try:
        fd = open("/dev/kvm", "wb")
    except:
        if(verbose):
            print(FAIL + ERROR_PREFIX + "KVM-PT is not loaded!" + ENDC)
        return 0

    try:
        ret = ioctl(fd, KVM_VMX_PT_GET_ADDRN, 0)
    except IOError:
        if(verbose):
            print(WARNING + WARNING_PREFIX + "Multi range tracing is not supported! Please upgrade to kernel 4.20-rc4!" + ENDC)
        ret = 1
    finally:
        fd.close()
    return ret

def vmx_pt_check_addrn(config):
    if config.argument_values.has_key("ip3") and config.argument_values["ip3"]:
        ip_ranges = 4
    elif config.argument_values.has_key("ip2") and config.argument_values["ip2"]:
        ip_ranges = 3
    elif config.argument_values.has_key("ip1") and config.argument_values["ip1"]:
        ip_ranges = 2
    elif config.argument_values.has_key("ip0") and config.argument_values["ip0"]:
        ip_ranges = 1
    else:
        ip_ranges = 0

    ret = vmx_pt_get_addrn()

    if(ip_ranges > ret):
        if ret > 1:
            print(FAIL + ERROR_PREFIX + "CPU supports only " + str(ret) + " hardware ip trace filters!" + ENDC)
        else:
            print(FAIL + ERROR_PREFIX + "CPU supports only " + str(ret) + " hardware ip trace filter!" + ENDC)
        return False
    return True


def check_vmx_pt():
    from fcntl import ioctl

    KVMIO = 0xAE
    KVM_VMX_PT_SUPPORTED = KVMIO << (8) | 0xe4

    try:
        fd = open("/dev/kvm", "wb")
    except:
        print(FAIL + ERROR_PREFIX + "KVM-PTis not loaded!" + ENDC)
        return False

    try:
        ret = ioctl(fd, KVM_VMX_PT_SUPPORTED, 0)
    except IOError:
        print(FAIL + ERROR_PREFIX + "VMX_PT is not loaded!" + ENDC)
        return False
    fd.close()

    if ret == 0:
        print(FAIL + ERROR_PREFIX + "Intel PT is not supported on this CPU!" + ENDC)
        return False


    return True


def check_apple_osk(config):
    if config.argument_values["macOS"]:
        if config.config_values["APPLE-SMC-OSK"] == "":
            print(FAIL + ERROR_PREFIX + "APPLE SMC OSK is missing in nyx.ini!" + ENDC)
            return False
    return True


def check_apple_ignore_msrs(config):
    if config.argument_values["macOS"]:
        try:
            f = open("/sys/module/dell/parameters/ignore_msrs")
            if not 'Y' in f.read(1):
                print(FAIL + ERROR_PREFIX + "KVM is not properly configured! Please execute the following command:" + ENDC + "\n\n\tsudo su\n\techo 1 > /sys/module/dell/parameters/ignore_msrs\n")
                return False
            else:
                return True
        except:
            pass
        finally:
            f.close()
        print(FAIL + ERROR_PREFIX + "KVM is not ready?!" + ENDC)
        return False
    return True


def check_nyx_ini():
    if not os.path.exists(os.path.dirname(sys.argv[0])+"/nyx.ini") and not os.path.exists("nyx.ini"):
        from common.config import FuzzerConfiguration
        FuzzerConfiguration(skip_args=True).create_initial_config()
        print(WARNING + WARNING_PREFIX + "nyx.ini file does not exist. Creating..." + ENDC)
        return False
    return True


def check_qemu_version(config):
    if not config.config_values["QEMU_KAFL_LOCATION"] or config.config_values["QEMU_KAFL_LOCATION"] == "":
        print(FAIL + ERROR_PREFIX + "QEMU_KAFL_LOCATION is not set in nyx.ini!" + ENDC)
        return False

    if not os.path.exists(config.config_values["QEMU_KAFL_LOCATION"]):
        print(FAIL + ERROR_PREFIX + "QEMU-PT executable does not exists..." + ENDC)
        return False

    output = ""
    try:
        proc = subprocess.Popen([config.config_values["QEMU_KAFL_LOCATION"], "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = proc.stdout.readline()
        proc.wait()
    except:
        print(FAIL + ERROR_PREFIX + "Binary is not executable...?" + ENDC)
        return False
    if not("QEMU-PT" in output and "(kAFL)" in output):
        print(FAIL + ERROR_PREFIX + "Wrong QEMU-PT executable..." + ENDC)
        return False
    return True

def check_cpu_num(config):
    import multiprocessing

    if 'p' not in config.argument_values:
        return True

    if int(config.argument_values["p"]) > int(multiprocessing.cpu_count()):
        print(FAIL + ERROR_PREFIX + "Only %d fuzzing processes are supported..." % (int(multiprocessing.cpu_count())) + ENDC)
        return False
    return True

def self_check():
    if not check_nyx_ini():
        return False
    #if not check_if_nativ_lib_compiled():
    #    return False
    if not check_version():
        return False
    if not check_packages():
        return False
    return True


def post_self_check(config):
    if not check_apple_ignore_msrs(config):
        return False
    if not check_apple_osk(config):
        return False
    if not check_qemu_version(config):
        return False
    if not vmx_pt_check_addrn(config):
        return False
    if not check_cpu_num(config):
        return False
    return True
