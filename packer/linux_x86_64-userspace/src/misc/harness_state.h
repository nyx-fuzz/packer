#pragma once

#include <stdbool.h>
#include <stdint.h>

/* harness state */
typedef struct harness_state_s{
    bool fast_exit_mode;
    bool asan_executable;
    bool legacy_file_mode;
    bool net_fuzz_mode;
    bool afl_mode;
    bool delayed_init;
    bool pt_auto_addr_range_a;
    bool pt_auto_addr_range_b;
    uint16_t nyx_net_port;
} harness_state_t;

harness_state_t* get_harness_state(void);
void set_harness_state(void);
