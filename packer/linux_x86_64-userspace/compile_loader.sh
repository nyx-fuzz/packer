mkdir -p bin64/
gcc -O0 -m64 -static -Werror src/loader.c -I../../ -o bin64/loader
gcc -O0 -m64 -static -Werror src/portio-enable.c -I../../ -o bin64/portio-enable
