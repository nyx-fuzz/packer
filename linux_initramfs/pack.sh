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
cd ../packer/linux_x86_64-userspace/ || exit
sh compile_loader.sh
cd - || exit
cp ../packer/linux_x86_64-userspace/bin64/loader rootTemplate/loader

# copy lib $arg1 listed in `ldconfig -p` to dir `rootTemplate`
copy_lib(){
	lib_name=$1
	# grep: get dependency of lib; sed: remove string's left part splited by "=>"
	lib_paths=$(ldconfig -p | grep -E  "$lib_name \(.*\) => " | sed -E "s/^.*=> //")
	if [ -z "$lib_paths" ]; then
		echo "lib $lib_name not found in ldconfig, consider install it"
		exit 1
	fi

	for lib_path in $lib_paths; do
	target_path="rootTemplate$lib_path"
	target_dir=$(dirname "$target_path")
	if [ ! -d "$target_dir" ] ; then
		mkdir -pv "$target_dir"
	fi
		cp -Lv "$lib_path" "$target_path"
	done
}
#cp /home/kafl/nyx_fuzzer_snapshot/snapshot_toy_examples/packer/linux_x86_64-userspace/bin64/loader rootTemplate/loader
chmod +x rootTemplate/loader
mkdir rootTemplate/lib/
mkdir rootTemplate/lib64/
mkdir rootTemplate/lib/i386-linux-gnu/
mkdir rootTemplate/lib/x86_64-linux-gnu/

copy_lib ld-linux.so.2
copy_lib ld-linux-x86-64.so.2
copy_lib libdl.so.2
copy_lib libc.so.6

# fix nasty nss bugs (getpwnam_r, ...)
copy_lib libnss_compat.so.2

cp -r "rootTemplate" "init"
sed '/START/c\./loader' init/init_template > init/init
chmod 755 "init/init"
cd "init" || exit

find . -print0 | cpio --null -ov --format=newc  2> /dev/null | gzip -9 > "../init.cpio.gz" 2> /dev/null
cd ../
rm -r ./init/


cp -r "rootTemplate" "init"
sed '/START/c\sh' init/init_template > init/init
chmod 755 "init/init"
cd "init" || exit

find . -print0 | cpio --null -ov --format=newc  2> /dev/null | gzip -9 > "../init_debug_shell.cpio.gz"  2> /dev/null
cd ../
rm -r ./init/

rm -r rootTemplate/lib/
rm -r rootTemplate/lib64/
rm rootTemplate/loader
