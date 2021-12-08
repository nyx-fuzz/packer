mkdir -p bin32/

if [ "$NO_PT_NYX" = "YES" ]
then
	EXTRA="-DNO_PT_NYX"
else
	EXTRA=""
fi

if [ "$LEGACY_MODE" = "ON" ]
then
  # old kAFL mode shared library
  gcc -shared -O0 -m32 -Werror -DLEGACY_MODE -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/misc/harness_state.c  src/netfuzz/syscalls.c -I../../ -o bin32/ld_preload_fuzz_legacy.so -ldl -Isrc
  gcc -shared -O0 -m32 -Werror -DLEGACY_MODE -DNO_PT_NYX -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/misc/harness_state.c  src/netfuzz/syscalls.c -I../../ -o bin32/ld_preload_fuzz_legacy_no_pt.so -ldl -Isrc
else
  # latest and greatest nyx shared library

  if [ "$NET_FUZZ" = "ON" ]
  then
    MODE="${UDP_MODE} ${CLIENT_MODE} ${DEBUG_MODE} ${STDOUT_STDERR_DEBUG}"
    echo "MODES => $MODE"
    clang -shared -g -O0 -m32 -Werror $EXTRA $MODE -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/misc/harness_state.c src/netfuzz/inject.c src/netfuzz/syscalls.c src/netfuzz/socket_cache.c -I../../ -DNET_FUZZ -I$NYX_SPEC_FOLDER -o bin32/ld_preload_fuzz.so -ldl -Isrc
    clang -shared -g -O0 -m32 -Werror -DNO_PT_NYX $EXTRA $MODE -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/misc/harness_state.c src/netfuzz/inject.c src/netfuzz/syscalls.c src/netfuzz/socket_cache.c -I../../ -DNET_FUZZ -I$NYX_SPEC_FOLDER -o bin32/ld_preload_fuzz_no_pt.so -ldl -Isrc

  else

  if [ -n "$NYX_SPEC_FOLDER" ]
    then
      gcc -shared -O0 -m32 -Werror -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/netfuzz/syscalls.c src/misc/harness_state.c -I../../  -I$NYX_SPEC_FOLDER -o bin32/ld_preload_fuzz.so -ldl -Isrc
      gcc -shared -O0 -m32 -Werror -DNO_PT_NYX -fPIC src/ld_preload_fuzz.c src/misc/crash_handler.c src/netfuzz/syscalls.c src/misc/harness_state.c -I../../  -I$NYX_SPEC_FOLDER -o bin32/ld_preload_fuzz_no_pt.so -ldl -Isrc
    fi
  fi
fi

gcc -m32  src/libnyx.c -o bin32/libnyx.so -shared -fPIC -Wall -std=gnu11 -Wl,-soname,libnyx.so

# pt mode builds
gcc -O0 -m32 -Werror src/htools/habort.c -I../../ -o bin32/habort
gcc -O0 -m32 -Werror src/htools/hcat.c -I../../ -o bin32/hcat
gcc -O0 -m32 -Werror src/htools/hget.c -I../../ -o bin32/hget
#gcc -O0 -m32 -Werror src/htools/hget_bulk.c -I../../agents -o bin32/hget_bulk
gcc -O0 -m32 -Werror src/htools/hpush.c -I../../ -o bin32/hpush

# no-pt mode builds
gcc -O0 -m32 -Werror -DNO_PT_NYX src/htools/habort.c -I../../ -o bin32/habort_no_pt
gcc -O0 -m32 -Werror -DNO_PT_NYX src/htools/hcat.c -I../../ -o bin32/hcat_no_pt
gcc -O0 -m32 -Werror -DNO_PT_NYX src/htools/hget.c -I../../ -o bin32/hget_no_pt
#gcc -O0 -m32 -Werror -DNO_PT_NYX src/htools/hget_bulk.c -I../../agents -o bin32/hget_bulk_no_pt
gcc -O0 -m32 -Werror -DNO_PT_NYX src/htools/hpush.c -I../../ -o bin32/hpush_no_pt

# loader support both modes (PT & NO-PT)
#gcc -O0 -m32 -static -Werror src/loader.c -I../../agents -o bin32/loader
