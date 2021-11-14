#pragma once

#include <stdint.h>


#define ADD_PADDING(max, type) uint8_t type ## _padding [max - sizeof(type)]

typedef struct interpeter_data_s{
  uint32_t executed_opcode_num; 
  bool ouf_of_data; 
  /* ... */
} __attribute__((packed)) interpeter_data_t;


typedef struct ijon_data_s{
  uint64_t max_data[256];
} __attribute__((packed)) ijon_data_t;

typedef struct ijon_trace_buffer_s{
  interpeter_data_t interpreter_data; 
  ADD_PADDING(2048, interpeter_data_t);

  /* 2k */
  ijon_data_t ijon_data;
} __attribute__((packed)) ijon_trace_buffer_t;

extern ijon_trace_buffer_t* ijon_trace_buffer; 


void ijon_max(uint8_t id, uint64_t value);
