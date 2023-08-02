#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/********************
 * Shared functions *
 ********************/

void afl_deserialize(uint8_t* buf, uint32_t size);

/********************************
 * Functions for custom mutator *
 ********************************/

int afl_packets_size();

void afl_delete_packet(int index);

size_t afl_get_packet(int index, void* buf, size_t size);

void afl_set_packet(int index, void* buf, size_t size);

size_t afl_serialize(void* buf, size_t size);

/****************************
 * Functions for ld_preload *
 ****************************/

int afl_has_next();

size_t afl_get_next(void* buf, size_t size);

#ifdef __cplusplus
}
#endif