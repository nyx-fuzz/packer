#pragma once

#include <stdbool.h>
#include <signal.h>


void config_handler(void);
void init_crash_handling(void);

/* test asan */
void fail(void);