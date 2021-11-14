mkdir -p bin64/
gcc -O0 -m64 -static -Werror src/loader.c -I../../ -o bin64/loader
