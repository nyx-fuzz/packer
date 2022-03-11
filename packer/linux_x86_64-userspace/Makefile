# Configuration options
CFLAGS += -DLEGACY_MODE   # build for AFL/kAFL frontend (Nyx-Net options not supported)
HTOOLS_CFLAGS += -static  # avoid dependencies for htools

VARIANTS := bin32 bin64 bin32_nopt bin64_nopt
.PHONY: $(VARIANTS)

bin32: export CFLAGS += -m32
bin64: export CFLAGS += -m64
bin32_nopt: export CFLAGS += -m32 -DNO_PT_NYX
bin64_nopt: export CFLAGS += -m64 -DNO_PT_NYX

all: $(VARIANTS)

clean:
	rm -rf $(VARIANTS)

$(VARIANTS):
	-mkdir -p $@
	$(MAKE) -C $@ -f ../Makefile $(HTOOLS) $(LDPRELOAD_LIB)

HTOOLS := habort hcat hget hpush loader # hget_bulk
HTOOLS_CFLAGS += -g -Og -Werror -I ../../../ $(CFLAGS)

habort: ../src/htools/habort.c
hget: ../src/htools/hget.c
hget_bulk: ../src/htools/hget_bulk.c
hpush: ../src/htools/hpush.c
hcat: ../src/htools/hcat.c
loader: ../src/loader.c

$(HTOOLS):
	$(CC) $(HTOOLS_CFLAGS) $^ -o $@

LDPRELOAD_LIB := ld_preload_fuzz.so
LDPRELOAD_SRCS := ../src/ld_preload_fuzz.c ../src/misc/crash_handler.c ../src/misc/harness_state.c ../src/netfuzz/syscalls.c
LDPRELOAD_CFLAGS += -shared -fPIC -ldl -g -Og -Werror -I../src -I../../../ $(CFLAGS)
LDPRELOAD_CFLAGS += -DLEGACY_MODE

$(LDPRELOAD_LIB): $(LDPRELOAD_SRCS)
	$(CC) $(LDPRELOAD_CFLAGS) $^ -o $@
