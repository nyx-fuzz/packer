# Nyx-Packer

<p>
<img align="right" width="200"  src="logo.png">
</p>

This repository contains the image packer for nyx VMs. It is used to perform a variety of tasks that create a functioning Nyx sharedir (which contains all bundled data needed to spawn and run a VM). This includes agent (and if needed target binaries), various scripts running in the VM, config files (which links the kernel or disc image), seeds etc.  

## Bug Reports and Contributions

Should you find a bug in this tool and need help fixing it, please make sure that the report includes the output dump and the (incomplete) output directory. If you found and fixed a bug on your own: We are very open to patches, please create a pull request!  

### License

This tool is provided under **GPLv2 license**, except for the `nyx.h` file, which is separately licensed under the **MIT license**. 
All busybox executables and the Linux kernel image (located in `./linux_initramfs`) were built from code licensed under the GNU General Public License version 2 (GPLv2).


**Free Software Hell Yeah!** 

Proudly provided by: 
* [Sergej Schumilo](http://schumilo.de) - sergej@schumilo.de / [@ms_s3c](https://twitter.com/ms_s3c)
* [Cornelius Aschermann](https://hexgolems.com) - cornelius@hexgolems.com / [@is_eqv](https://twitter.com/is_eqv)
