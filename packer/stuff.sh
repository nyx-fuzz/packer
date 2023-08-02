#!/bin/bash

#
#   Pack and setup for fuzzing
#

cd ~/aflpp_nyx/nyx_mode/packer/packer

#python3 nyx_packer.py --purge -spec ~/nyxnet/nyx-net/targets/specs/echoserver --setup_folder ~/nyxnet/nyx-net/targets/extra_folders/echoserver_extra_folder --nyx_net --nyx_net_port 1234 ~/nyxnet/nyx-net/targets/setup_scripts/build/echoserver/echoserver /tmp/echo_packed spec instrumentation
python3 nyx_packer.py --nyx_net_debug_mode --purge -spec ~/nyxnet/nyx-net/targets/specs/echoserver --setup_folder ~/nyxnet/nyx-net/targets/extra_folders/echoserver_extra_folder --nyx_net --nyx_net_port 1234 ~/nyxnet/nyx-net/targets/setup_scripts/build/echoserver/echoserver /tmp/echo_packed spec instrumentation

python3 nyx_config_gen.py /tmp/echo_packed Kernel

kill -9 $(pgrep qemu)
rm -rf /tmp/out

echo "ready to fuzz"
