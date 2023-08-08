#include <sys/types.h>
#include <stdint.h>

#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/********************
 * Shared functions *
 ********************/

/// @brief Deserializes a buffer into a protobuf message. This resets the state for `afl_has_next()` and `afl_get_next()`
/// @param buf Buffer from which protobuf will be deserialized from
/// @param size Size of buf
void afl_deserialize(uint8_t* buf, uint32_t size);

/********************************
 * Functions for custom mutator *
 ********************************/

/// @brief Gets the number of packets
/// @return The number of packets
int afl_packets_size();

/// @brief Delete the nth packet
/// @param index Index of packet to delete
void afl_delete_packet(int index);

/// @brief Gets the packet data at index n and copies up to size bytes into buf
/// @param index Index of packet to get
/// @param buf Buffer packet is written to
/// @param size Size of buf
/// @return 
size_t afl_get_packet(int index, void* buf, size_t size);

/// @brief Replaces a packet at index n with the contents of buf
/// @param index Index of packet to replace
/// @param buf Buffer to copy packet data from
/// @param size Size of buf
void afl_set_packet(int index, void* buf, size_t size);

/// @brief Serializes a protobuf message into a buffer
/// @param buf Buffer that the message will be serialized into
/// @param size Size of buf
/// @return 
size_t afl_serialize(void* buf, size_t size);

/****************************
 * Functions for ld_preload *
 ****************************/

/// @brief Checks if there is another packet in the current set of deserialized packets that has not yet been fetched
/// @return True if there is another packet to get
bool afl_has_next();

/// @brief Get a pointer to the next packet in the current set of deserialized packets
/// @param out_size Pointer to size of the packet data, set by the function
/// @return Pointer to the packet data, also sets out_size
const char* afl_get_next(size_t* out_size);

#ifdef __cplusplus
}
#endif