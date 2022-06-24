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

# copy all lib listed in `lld $arg1` to dir `rootTemplate`
copy_lib_by_prog(){
	prog_name=$1
	# grep: get dyn dependency instead of static lib
	# sed: remove string's left part splited by "=>"
	# awk: get the first part of output(lib's absolute path)
	lib_paths=$(ldd $prog_name | grep "=>" | sed -E "s/^.*=> //" | awk '{print $1}')

	for lib_path in $lib_paths; do
	target_path="rootTemplate$lib_path"
	target_dir=$(dirname "$target_path")
	if [ ! -d "$target_dir" ] ; then
		mkdir -pv "$target_dir"
	fi
	if [ ! -c "$target_path" ] ; then
		cp -L "$lib_path" "$target_path"
	fi	
	done
}

copy_lib_by_name(){
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
mkdir rootTemplate/usr/lib/
mkdir rootTemplate/usr/lib64/
mkdir rootTemplate/usr/lib32/
mkdir rootTemplate/lib/i386-linux-gnu/
mkdir rootTemplate/lib/x86_64-linux-gnu/

#create symbol link for lib
cd ./rootTemplate
ln -s usr/lib   lib
ln -s usr/lib64 lib64
ln -s usr/lib32 lib32
cd -

# compile esstential tools to get correct lib dependency
echo "compiling esstential tools"
cd ../packer/linux_x86_64-userspace/
sh compile_32.sh 1> /dev/null || exit 1
sh compile_64.sh 1> /dev/null || exit 1
cd -

# copy dyn-link libs for tools
for prog_name in $(ls -d ../packer/linux_x86_64-userspace/bin32/*) ; do
	copy_lib_by_prog $prog_name
done

for prog_name in $(ls -d ../packer/linux_x86_64-userspace/bin64/*) ; do
	copy_lib_by_prog $prog_name
done

copy_lib_by_name ld-linux.so.2
copy_lib_by_name ld-linux-x86-64.so.2
copy_lib_by_name libdl.so.2
copy_lib_by_name libc.so.6

# fix nasty nss bugs (getpwnam_r, ...)
copy_lib_by_name libnss_compat.so.2

cp -r "rootTemplate" "init"
sed '/START/c\./loader' init/init_template > init/init
chmod 755 "init/init"
cd "init" || exit

find . -print0 | cpio --null -ov --format=newc | gzip -9 > "../init.cpio.gz"
cd ../
rm -r ./init/


cp -r "rootTemplate" "init"
sed '/START/c\sh' init/init_template > init/init
chmod 755 "init/init"
cd "init" || exit

find . -print0 | cpio --null -ov --format=newc | gzip -9 > "../init_debug_shell.cpio.gz" 
cd ../
rm -r ./init/

# rm -r rootTemplate/lib/
# rm -r rootTemplate/lib64/
rm rootTemplate/loader
