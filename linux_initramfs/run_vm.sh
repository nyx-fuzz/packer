qemu-system-x86_64 -kernel bzImage-linux-4.15-rc7 -initrd init_debug_shell.cpio.gz -serial mon:stdio -enable-kvm -k de -m 300  -append "root=/dev/sda console=ttyS0" -nographic 
