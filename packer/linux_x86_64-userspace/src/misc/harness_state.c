#define _GNU_SOURCE

#include <stdlib.h>
#include <dlfcn.h>
#include "misc/harness_state.h"
#include "netfuzz/syscalls.h"
#include "nyx.h"

//#define DEBUG_HARNESS_STATE

static bool harness_state_ready = false;

harness_state_t* get_harness_state(void){
    static harness_state_t harness_state = {0}; 
    if (!harness_state_ready){
        harness_state_ready = true;
        set_harness_state();
    }
    return &harness_state;
}

static bool early_check_env(const char* env){
    char buffer [1024];
    snprintf (buffer, 1024, "[ -z \"$%s\" ]", env);
    return !!system(buffer);
}

static bool check_env(const char* env){
    bool ret = false;
    ret = !!real_getenv(env);
    if(!ret){
        ret = early_check_env(env);
    }
    return ret;
}

void set_harness_state(void){
    harness_state_t* state = get_harness_state();

    state->fast_exit_mode = check_env("NYX_FAST_EXIT_MODE");
    state->asan_executable = check_env("NYX_ASAN_EXECUTABLE");
    state->legacy_file_mode = check_env("NYX_LEGACY_FILE_MODE");
    state->net_fuzz_mode = check_env("NYX_NET_FUZZ_MODE");
    state->afl_mode = check_env("NYX_AFL_PLUS_PLUS_MODE");
    state->delayed_init = check_env("DELAYED_NYX_FUZZER_INIT");
    state->pt_auto_addr_range_a = check_env("NYX_PT_RANGE_AUTO_CONF_A");
    state->pt_auto_addr_range_b = check_env("NYX_PT_RANGE_AUTO_CONF_B");

    if(real_getenv("NYX_NET_PORT")){
        state->nyx_net_port = (uint16_t)strtol(real_getenv("NYX_NET_PORT"), NULL, 10);
    }
    else{
        state->nyx_net_port = 0;
    }

#ifdef DEBUG_HARNESS_STATE
    hprintf("fast_exit_mode: %d\n", state->fast_exit_mode);
    hprintf("asan_executable: %d\n", state->asan_executable);
    hprintf("legacy_file_mode: %d\n", state->legacy_file_mode);
    hprintf("net_fuzz_mode: %d\n", state->net_fuzz_mode);
    hprintf("afl_mode: %d\n", state->afl_mode);
    hprintf("delayed_init: %d\n", state->delayed_init);
    hprintf("pt_auto_addr_range_a: %d\n", state->pt_auto_addr_range_a);
    hprintf("pt_auto_addr_range_b: %d\n", state->pt_auto_addr_range_b);
    hprintf("NYX_NET_PORT: %d\n", state->nyx_net_port);
#endif

    harness_state_ready = true;
}
