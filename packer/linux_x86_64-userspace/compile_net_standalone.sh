

gcc -shared -fPIC -o inject.so -c src/netfuzz/inject.c src/netfuzz/socket_cache.c 