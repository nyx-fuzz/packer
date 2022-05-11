#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include "nyx.h"
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv){
  char* error_message = NULL;
  int ret;

  if(!is_nyx_vcpu()){
    printf("Error: NYX vCPU not found!\n");
    return 0;
  }

  if(argc < 1){
    printf("Usage: <habort>\n");
    return 1;
  }

  if (argc == 2){
    ret = asprintf(&error_message, "USER_ABORT called: %s", argv[1]);
    if (ret != -1) {
      kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)error_message);
      return 0;
    }
  }
  kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)"USER_ABORT called!");
  return 0;
}
