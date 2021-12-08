#!/bin/sh
# 
# This file is part of Redqueen.
#
# Sergej Schumilo, 2019 <sergej@schumilo.de> 
# Cornelius Aschermann, 2019 <cornelius.aschermann@rub.de> 
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Redqueen.  If not, see <http://www.gnu.org/licenses/>.
#

#cd ../agents/linux_x86_64/
#bash compile.sh
#cd -

#cp  ../agents/linux_x86_64/bin/loader/loader rootTemplate/loader
cd ../packer/linux_x86_64-userspace/
sh compile_loader.sh
cd -
cp ../packer/linux_x86_64-userspace/bin64/loader rootTemplate/loader
#cp /home/kafl/nyx_fuzzer_snapshot/snapshot_toy_examples/packer/linux_x86_64-userspace/bin64/loader rootTemplate/loader
chmod +x rootTemplate/loader
mkdir rootTemplate/lib/
mkdir rootTemplate/lib64/
mkdir rootTemplate/lib/i386-linux-gnu/
mkdir rootTemplate/lib/x86_64-linux-gnu/

cp -L /lib/ld-linux.so.2 rootTemplate/lib/ld-linux.so.2
cp -L /lib64/ld-linux-x86-64.so.2 rootTemplate/lib64/ld-linux-x86-64.so.2
cp -L /lib/x86_64-linux-gnu/libdl.so.2 rootTemplate/lib/x86_64-linux-gnu/libdl.so.2
cp -L /lib/x86_64-linux-gnu/libc.so.6 rootTemplate//lib/x86_64-linux-gnu/libc.so.6
cp -L /lib32/libc.so.6  rootTemplate//lib32/libc.so.6
cp -L /lib/ld-linux.so.2 rootTemplate/lib/ld-linux.so.2
cp -L /lib32/libdl.so.2 rootTemplate/lib32/libdl.so.2

# fix nasty nss bugs (getpwnam_r, ...)
cp /lib/x86_64-linux-gnu/libnss_compat.so.2 rootTemplate//lib/x86_64-linux-gnu/

cp -r "rootTemplate" "init"
sed '/START/c\./loader' init/init_template > init/init
chmod 755 "init/init"
cd "init"

find . -print0 | cpio --null -ov --format=newc  2> /dev/null | gzip -9 > "../init.cpio.gz" 2> /dev/null
cd ../
rm -r ./init/


cp -r "rootTemplate" "init"
sed '/START/c\sh' init/init_template > init/init
chmod 755 "init/init"
cd "init"

find . -print0 | cpio --null -ov --format=newc  2> /dev/null | gzip -9 > "../init_debug_shell.cpio.gz"  2> /dev/null
cd ../
rm -r ./init/

rm -r rootTemplate/lib/
rm -r rootTemplate/lib64/
rm rootTemplate/loader
