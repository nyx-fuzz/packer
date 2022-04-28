
#include <stdio.h>
#include <stdint.h>
#include "nyx.h"
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>

bool pt_mode = true;

static inline uint64_t perform_hypercall(uintptr_t rbx, uintptr_t rcx){
  if(pt_mode){
    return KAFL_HYPERCALL_PT(rbx, rcx);
  }
  else{
    return KAFL_HYPERCALL_NO_PT(rbx, rcx);
  }
}

static inline uint64_t get_address(char* identifier)
{
    FILE * fp;
    char * line = NULL;
    ssize_t read;
    ssize_t len;
    char *tmp;
    uint64_t address = 0x0;
    uint8_t identifier_len = strlen(identifier);

    fp = fopen("/proc/kallsyms", "r");
    if (fp == NULL){
        return address;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        if(strlen(line) > identifier_len && !strcmp(line + strlen(line) - identifier_len, identifier)){
                address = strtoull(strtok(line, " "), NULL, 16);
                break;
        }
    }

    fclose(fp);
    if (line){
        free(line);
    }
    return address;
}


bool download_file(const char* filename, const char* dst){
  void* stream_data = mmap((void*)NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
 
  FILE* f = NULL;

  uint64_t bytes = 0;
  uint64_t total = 0;

  do{
    strcpy(stream_data, filename);
    bytes = perform_hypercall(HYPERCALL_KAFL_REQ_STREAM_DATA, (uintptr_t)stream_data);

    if(bytes == 0xFFFFFFFFFFFFFFFFUL){
      printf("HYPERVISOR: ERROR\n");
      return false;
    }

    if(f == NULL){
      f = fopen(dst, "w+");
    }

      fwrite(stream_data, 1, bytes, f);

      total += bytes;

    } while(bytes);

    printf("%"PRIu64" bytes received from hypervisor! (%s)\n", total, filename);

    if(f){
      fclose(f);
      return true;
  }
  return false;
}

int main(int argc, char** argv){

	uint64_t panic_handler = 0x0;
	uint64_t kasan_handler = 0x0;
	int ignored;

  if(!is_nyx_vcpu()){
    printf("Error: NYX vCPU not found!\n");
    return 0;
  }
  if(argc == 1){
    

    panic_handler = get_address("T panic\n");
    printf("Kernel Panic Handler Address:\t%"PRIu64"\n", panic_handler);

    kasan_handler = get_address("t kasan_report_error\n");
    if (kasan_handler){
      printf("Kernel KASAN Handler Address:\t%"PRIu64"\n", kasan_handler);
    }

    /* check if we're running on an KVM-PT host or vanilla kernel first */
    int nyx_cpu_type = get_nyx_cpu_type();

    if(nyx_cpu_type == nyx_cpu_v1){
      pt_mode = true;
    }
    else if(nyx_cpu_type == nyx_cpu_v2){
      pt_mode = false;
    }
    else{
      fprintf(stderr, "ERROR: Unkown NYX CPU type found!\n");
      abort();
    }


	  perform_hypercall(HYPERCALL_KAFL_LOCK, 0);

    if(pt_mode){
      if(!download_file("hget", "hget")){
        perform_hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)"Error: Can't get file 'hget'\n");
      }

      if(!download_file("fuzz.sh", "fuzz.sh")){
        perform_hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)"Error: Can't get file 'fuzz.sh'\n");
      }
    }
    else{
      if(!download_file("hget_no_pt", "hget")){
        perform_hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)"Error: Can't get file 'hget_no_pt'\n");
      }

      if(!download_file("fuzz_no_pt.sh", "fuzz.sh")){
        perform_hypercall(HYPERCALL_KAFL_USER_ABORT, (uintptr_t)"Error: Can't get file 'fuzz_no_pt.sh'\n");
      }
    }

    /* initial fuzzer handshake ... obsolete shit */
    perform_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    perform_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    /* submit panic address */
    perform_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_handler);
    /* submit KASan address */
    if (kasan_handler){
      perform_hypercall(HYPERCALL_KAFL_SUBMIT_KASAN, kasan_handler);
    }

    ignored = system("chmod +x fuzz.sh");
    ignored = system("./fuzz.sh");
    while(true){}
  }
  printf("Usage: <loader>\n");
  return 0;
}
