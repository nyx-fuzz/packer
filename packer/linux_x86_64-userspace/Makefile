# Configuration options
CFLAGS += -DLEGACY_MODE   # build for AFL/kAFL frontend (Nyx-Net options not supported)
HTOOLS_CFLAGS += -static  # avoid dependencies for htools
#CFLAGS += -DNO_PT_NYX    # use VMWare backdoor (instead of Nyx-KVM vmcall)


VARIANTS := bin64 bin32
.PHONY: $(VARIANTS)

bin32: export MARCH := -m32
bin64: export MARCH := -m64

all: $(VARIANTS)

clean:
	rm -rf $(VARIANTS)

bin32:
	-mkdir -p bin32
	$(MAKE) -C bin32 -f ../Makefile $(HTOOLS) $(LDPRELOAD_LIB)

bin64:
	test -d bin64 || mkdir -p bin64
	$(MAKE) -C bin64 -f ../Makefile $(HTOOLS) $(LDPRELOAD_LIB)

HTOOLS := habort hcat hget hpush loader # hget_bulk
HTOOLS_CFLAGS += -g -Og -Werror -I ../../../ $(MARCH) $(CFLAGS)

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
LDPRELOAD_CFLAGS += -shared -fPIC -ldl -g -Og -Werror -I../src -I../../../ $(MARCH) $(CFLAGS)
LDPRELOAD_CFLAGS += -DLEGACY_MODE

$(LDPRELOAD_LIB): $(LDPRELOAD_SRCS)
	$(CC) $(LDPRELOAD_CFLAGS) $^ -o $@
