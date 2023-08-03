#define _GNU_SOURCE

#include <sys/mman.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <time.h>
#include <link.h>
#include <stdbool.h>

#include "nyx.h"
#include "misc/crash_handler.h"
#include "misc/harness_state.h"

//#define HYPERCALL_KAFL_RELEASE_DEBUG

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

__attribute__((weak)) extern unsigned int __afl_final_loc;
unsigned int* __afl_final_loc_ptr = &__afl_final_loc;

__attribute__((weak)) extern uint32_t __afl_dictionary_len;
uint32_t* __afl_dictionary_len_ptr = &__afl_dictionary_len;

__attribute__((weak)) extern uint8_t* __afl_dictionary;
uint8_t** __afl_dictionary_ptr = &__afl_dictionary;

size_t input_buffer_size = 0;
bool fuzz_process = false;

/* dump nyx-net payload */
bool payload_mode = false;

#ifdef DEBUG_MODE
#define DEBUG(f_, ...) hprintf((f_), ##__VA_ARGS__)
#else
#define DEBUG(f_, ...) 
#endif

//#ifdef NET_FUZZ
#include "netfuzz/syscalls.h"
//#endif


#ifndef LEGACY_MODE
#include "interpreter.h"
#else
extern void __assert(const char *func, const char *file, int line, const char *failedexpr);
#define INTERPRETER_ASSERT(x) do { if (x){}else{ __assert(__func__, __FILE__, __LINE__, #x);} } while (0)
#define ASSERT(x) INTERPRETER_ASSERT(x)
#endif

#include "ijon_extension.h"


#define ASAN_EXIT_CODE 101
//#define REDIRECT_STDERR_TO_HPRINTF
//#define REDIRECT_STDOUT_TO_HPRINTF




bool fuzzer_ready = false;



#ifndef LEGACY_MODE
interpreter_t* vm;
#ifdef NET_FUZZ
socket_state_t vm_state;
#else
fd_state_t vm_state;
#endif
#endif

ssize_t (*fptr_read)(int fd, void *data, size_t size);
ssize_t (*fptr_getline)(char **lineptr, size_t *n, FILE *stream);


ijon_trace_buffer_t* ijon_trace_buffer = NULL; 
void* trace_buffer = NULL;


void ijon_max(uint8_t id, uint64_t value){
  if (ijon_trace_buffer && ijon_trace_buffer->ijon_data.max_data[id] < value){
    //hprintf("%s: %d %ld\n", __func__, id, value);
    ijon_trace_buffer->ijon_data.max_data[id] = value;
  }
}


void create_tmp_snapshot_handler(void){
    /* todo */
}

#ifndef LEGACY_MODE
size_t min_size_t(size_t a, size_t b){
    return a<b ? a : b;
}

/* don't enable this option for super mario */
/* TODO: make this option opt-in */
#ifdef NET_FUZZ
//#define EARLY_EXIT_NODES 35
#endif

static void dump_payload(void* buffer, size_t len){
    static bool init = false;
    static kafl_dump_file_t file_obj = {0};

    if (!init){
        file_obj.file_name_str_ptr = (uint64_t)"reproducer.py";
        file_obj.append = 0;
        file_obj.bytes = 0;
        kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t) (&file_obj));
        init=true;
    }

    file_obj.append = 1;
    file_obj.bytes = len;
    file_obj.data_ptr = (uint64_t)buffer;
    kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uint64_t) (&file_obj));
}

void hexdump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		hprintf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			hprintf(" ");
			if ((i+1) % 16 == 0) {
				hprintf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					hprintf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					hprintf("   ");
				}
				hprintf("|  %s \n", ascii);
			}
		}
	}
}
 

void hprintf_payload(char* data, size_t len){

    if(!payload_mode){
        return;
    }

    //hprintf("PROCESSING %d\n", len);
    char* buffer = malloc((len*4) + 25);
    memset(buffer, 0, (len*4) + 25);

    for(int i = 0; i < len; i++){
        sprintf(buffer+(i*4), "\\x%02X", ((unsigned char*)data)[i]);
    }

    //hprintf("=> STR: %s\n", buffer);
    //hexdump(data, len);

    char* tmp = NULL;
    //asprintf(&tmp, "packet( inputs=[], borrows=[], data=\"%s\")\n", buffer);
    asprintf(&tmp, "packet(data=\"%s\")\n", buffer);
    dump_payload(tmp, strlen(tmp));

    free(tmp);
    free(buffer);
}

/* TODO: check via env var */
//#define COPY_PAYLOAD_MODE


ssize_t call_vm(void *data, size_t max_size, bool return_pkt_size, bool disable_dump_mode){

#ifdef EARLY_EXIT_NODES
    static int count = 0;
#endif


#ifdef UDP_MODE
    vm->user_data->len = max_size; 
    vm->user_data->data = data;
    if(interpreter_run(vm)==0){
        return -1;
    }

#ifdef EARLY_EXIT_NODES
    count++;

    if (count >= EARLY_EXIT_NODES){
        return -1;
    }
#endif

    if(vm->user_data->closed){
        return -1; /* -1 -> EOF */
    }

    //hprintf("max: %d / pkt_len: %d / len: %d\n", max_size, vm->user_data->pkt_len, vm->user_data->len);
    if(return_pkt_size && max_size < vm->user_data->len){
//#ifdef COPY_PAYLOAD_MODE 
        if(payload_mode && !disable_dump_mode){
            hprintf_payload(vm->user_data->data, vm->user_data->len);
        }
        //hprintf("%d vs %d\n", vm->user_data->pkt_len, max_size);
//#endif
        return vm->user_data->len;
    }
    else{
//#ifdef COPY_PAYLOAD_MODE  
        if(payload_mode && !disable_dump_mode){
            hprintf_payload(vm->user_data->data, vm->user_data->len);
        }
//#endif
        return vm->user_data->len;
    }
#else

    #define PACKET_BUFFER_SIZE (1<<14)
    static char data_buffer[PACKET_BUFFER_SIZE];
    static size_t available_data= 0;
    static size_t next_data = 0;

    if(available_data == 0){
        vm->user_data->len = PACKET_BUFFER_SIZE;
        vm->user_data->data = &data_buffer[0];
            
        //hprintf("%s: 1: %p\n", __func__, vm);
        //hprintf("%s: 2: %p\n", __func__, vm->user_data);
        //hprintf("%s: 3: %p\n", __func__, vm->user_data->len);

        if(interpreter_run(vm)==0){
            DEBUG("%s: out of data\n", __func__);
            return -1;
        }

#ifdef EARLY_EXIT_NODES
        count++;

        if (count >= EARLY_EXIT_NODES){
            //hprintf("EARLY EXIT\n");
            return -1;
        }
#endif

        if(vm->user_data->closed){
            DEBUG("%s: closed\n", __func__);

            return -1; /* -1 -> EOF */
        }
        available_data = vm->user_data->len;
        next_data = 0;
    }

    size_t num_copied = min_size_t(available_data, max_size);
    /*
    if(available_data < num_copied){
        hprintf("WARNING: num_copied: %d / num_copied: %d\n", available_data, num_copied);
    }
    */
    memcpy(data, &data_buffer[next_data], num_copied);
    available_data-=num_copied;
    next_data+=num_copied;

    DEBUG("CALL_VM %d -> %d\n", max_size, num_copied);
//#ifdef COPY_PAYLOAD_MODE  
    if(payload_mode && !disable_dump_mode){
        hprintf_payload(data, num_copied);
    }
//#endif
    //return 0;
    return num_copied;
#endif
}

#ifndef NET_FUZZ
ssize_t read(int fd, void *data, size_t size) {

  if(fuzzer_ready){
    if(fd == 0){

        ssize_t return_value = call_vm(data, size, false, false);
        //hprintf("%s: %lx\n", __func__, return_value);

        if(return_value == -1){
        return 0;
        }
        return return_value;
    }
  }
  return fptr_read(fd, data, size);
}

ssize_t getline(char **lineptr, size_t *n, FILE *stream){
  if(fileno(stream) == 0){
    *lineptr = malloc(128);
    //printf("%p\n", *lineptr);
    ssize_t size = call_vm(*lineptr, 126, false, false);
    ASSERT(size <= 126);
    if(size == -1){
      return -1; /* EOF*/
    }
    (*lineptr)[size] = '\n';
    (*lineptr)[size+1] = 0;
    return size; /* zero is not EOF, instead return -1 */
  }
  return fptr_getline(lineptr, n, stream);
}
#endif

static void setup_interpreter(void* payload_buffer) {
  uint64_t* offsets = (uint64_t*)payload_buffer;
  //hprintf("checksum: %lx, %lx\n",offsets[0], INTERPRETER_CHECKSUM);
  ASSERT(offsets[0] == INTERPRETER_CHECKSUM);
  ASSERT(offsets[1] < 0xffffff);
  ASSERT(offsets[2] < 0xffffff);
  ASSERT(offsets[3] < 0xffffff);
  ASSERT(offsets[4] < 0xffffff);
  uint64_t* graph_size = &offsets[1];
  uint64_t* data_size = &offsets[2];
  
  //printf("graph_size: %d\n", graph_size);
  //printf("data_size: %d\n", graph_size);
  //printf("graph_offset: %d\n", offsets[3]);
  //printf("data_offset: %d\n", offsets[4]);
  
  uint16_t* graph_ptr = (uint16_t*)(payload_buffer+offsets[3]);
  uint8_t* data_ptr = (uint8_t*)(payload_buffer+offsets[4]);
  ASSERT(input_buffer_size != 0);
  ASSERT(offsets[3]+(*graph_size)*sizeof(uint16_t) <= input_buffer_size);
  ASSERT(offsets[4]+*data_size <= input_buffer_size);
  init_interpreter(vm, graph_ptr, (size_t*)graph_size, data_ptr, (size_t*)data_size, (void*)&ijon_trace_buffer->interpreter_data.executed_opcode_num);
  interpreter_user_init(vm);
  vm->user_data = &vm_state;
}
#endif



/* fuzz */

int _mlock(void* dst, size_t size) {
    return syscall(SYS_mlock, dst, size);
}

int _munlock(void* dst, size_t size) {
    return syscall(SYS_munlock, dst, size);
}

int _mlockall(int flags){
    return syscall(SYS_mlockall, flags);
}

pid_t _fork(void){
    return syscall(SYS_fork);
}

long int random(void){
    return 0;
}

int rand(void){
    return 0;
}

static inline uint64_t bench_start(void)
{
  unsigned  cycles_low, cycles_high;
  asm volatile( "CPUID\n\t" // serialize
                "RDTSC\n\t" // read clock
                "MOV %%edx, %0\n\t"
                "MOV %%eax, %1\n\t"
                : "=r" (cycles_high), "=r" (cycles_low)
                :: "%rax", "%rbx", "%rcx", "%rdx" );
  return ((uint64_t) cycles_high << 32) | cycles_low;
}

static void debug_time(void){
    time_t timer;
    char buffer[26];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    hprintf("Time: %s - TSC: %lx\n", buffer, bench_start);
}


typedef struct address_range_s{
    char* name;
    bool found;
    uintptr_t start;
    uintptr_t end; 

    uintptr_t ip0_a;
    uintptr_t ip0_b;

    uintptr_t ip1_a;
    uintptr_t ip1_b;
} address_range_t;

static int callback(struct dl_phdr_info *info, size_t size, void *data){
    address_range_t* ar = (address_range_t*) data;
    if(ar){
        if(!!strstr(info->dlpi_name, ar->name)){
            char *type;
            int p_type, j;

            for (j = 0; j < info->dlpi_phnum; j++) {
                if(j == 0){
                    ar->start = (uintptr_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
                    continue;
                }

                if(j == info->dlpi_phnum-1){
                    ar->end = (uintptr_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr) + info->dlpi_phdr[j].p_memsz;
                    ar->found = true;
                    break;
                }
            }
        }
    }
    return 0;
}

void calc_address_range(address_range_t* ar){

    dl_iterate_phdr(callback, (void*)ar);

    if(ar->found){
        ar->ip0_a = 0x1000UL;
        ar->ip0_b = ar->start-1;

        ar->ip1_a = ar->end;
#if defined(__i386__)
        ar->ip1_b = 0xfffff000;
#elif defined(__x86_64__)
        ar->ip1_b = 0x7ffffffff000;
#endif
    }
}

/* 
    Enable this option to boost targets running in reload mode. 
    Breaks non-reload mode.

     ** Experimental stuff as always! **
*/
void fast_exit(void){
#ifdef HYPERCALL_KAFL_RELEASE_DEBUG
    hprintf("HYPERCALL_KAFL_RELEASE in %s %d (%d)\n", __func__, __LINE__, fuzz_process);
#endif
    if(fuzz_process){
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
}

 void pthread_exit(void *retval){
     hprintf("%s: sig:\n", __func__);
    while(1){}
 }

#ifdef NET_FUZZ
void exit(int status){
#ifdef HYPERCALL_KAFL_RELEASE_DEBUG
    hprintf("HYPERCALL_KAFL_RELEASE in %s %d (%d)\n", __func__, __LINE__, fuzz_process);
#endif
    if(fuzz_process){
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }

    /* remove the following **two** lines if target runs as daemon (detached from termianl) */
    void (*real_exit)(int) = dlsym(RTLD_NEXT,"exit");
    real_exit(status);
    while(1){}
}
#endif

int raise(int sig){
    hprintf("%s: sig: %d\n", __func__, sig);
    while(1){}
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    return 0;
}

int kill(pid_t pid, int sig){
    hprintf("%s: sig: %d [PID:%d]\n", __func__, sig, pid);
    while(1){}
}


#ifdef NET_FUZZ
void _exit(int status){
    if(fuzz_process){
    #ifdef HYPERCALL_KAFL_RELEASE_DEBUG
        hprintf("HYPERCALL_KAFL_RELEASE in %s %d\n", __func__, __LINE__);
    #endif
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
    else{
        real__exit(0);
    }
    while(1){}
}
#endif

void capabilites_configuration(bool timeout_detection, bool agent_tracing, bool ijon_tracing){

    static bool done = false;

    if(!done){
        init_syscall_fptr();

        hprintf("[capablities] agent_tracing: %d\n", agent_tracing);
        /* configuration shit */
        host_config_t host_config;
        kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

        if(host_config.host_magic != NYX_HOST_MAGIC){
            habort("Error: NYX_HOST_MAGIC not found in host configuration - You are probably using an outdated version of QEMU-Nyx...");
        }

        if(host_config.host_version != NYX_HOST_VERSION){ 
            habort("Error: NYX_HOST_VERSION not found in host configuration - You are probably using an outdated version of QEMU-Nyx...");
        }

        hprintf("[capablities] host_config.bitmap_size: 0x%"PRIx64"\n", host_config.bitmap_size);
        hprintf("[capablities] host_config.ijon_bitmap_size: 0x%"PRIx64"\n", host_config.ijon_bitmap_size);
        hprintf("[capablities] host_config.payload_buffer_size: 0x%"PRIx64"\n", host_config.payload_buffer_size);

        input_buffer_size = host_config.payload_buffer_size;

        agent_config_t agent_config = {0};

        agent_config.agent_magic = NYX_AGENT_MAGIC;
        agent_config.agent_version = NYX_AGENT_VERSION;
        agent_config.agent_timeout_detection = (uint8_t)timeout_detection;
        agent_config.agent_tracing = (uint8_t)agent_tracing;
        agent_config.agent_ijon_tracing = 1; //(uint8_t) ijon_tracing; /* fix me later */

        /* AFL++ LTO support */ 
        agent_config.coverage_bitmap_size = host_config.bitmap_size;
        if (get_harness_state()->afl_mode && __afl_final_loc_ptr){
            unsigned int map_size = __afl_final_loc == 0 ? 65536 : __afl_final_loc;
            hprintf("[capablities] overwriting bitmap_size: 0x%"PRIx64"\n", map_size);
            agent_config.coverage_bitmap_size = map_size;
        }

        trace_buffer = mmap((void*)NULL, agent_config.coverage_bitmap_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        memset(trace_buffer, 0xff, agent_config.coverage_bitmap_size);

        ijon_trace_buffer = mmap((void*)NULL, host_config.ijon_bitmap_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        memset(ijon_trace_buffer, 0xff, host_config.ijon_bitmap_size);

        agent_config.trace_buffer_vaddr = (uintptr_t)trace_buffer;
        agent_config.ijon_trace_buffer_vaddr = (uintptr_t)ijon_trace_buffer;

#ifdef NET_FUZZ
        agent_config.agent_non_reload_mode = 0; //(uint8_t) ijon_tracing; /* fix me later */
#else
        agent_config.agent_non_reload_mode = get_harness_state()->fast_exit_mode;

#endif

        kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);
        
        /* read debug flag */

        if(agent_config.dump_payloads){
            hprintf("[capablities] payload mode enabled\n");
            payload_mode = true;
            //abort();
        }

        
        done = true;
    }
}


void dump_mappings(void){
    char filename[256];

    char* buffer = malloc(0x1000);

    kafl_dump_file_t file_obj = {0};


    file_obj.file_name_str_ptr = (uintptr_t)"proc_maps.txt";
    file_obj.append = 0;
    file_obj.bytes = 0;
    kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t) (&file_obj));
    file_obj.append = 1;


  	snprintf(filename, 256, "/proc/%d/maps", getpid());

	if(access(filename, R_OK) != 0){
		return;
	}

  	FILE* f = fopen(filename, "r");
    uint32_t len = 0;
    while(1){
  	    len = fread(buffer, 1, 0x1000, f);
        if(!len){
            break;
        }
        else{

            file_obj.bytes = len;
            file_obj.data_ptr = (uintptr_t)buffer;
            kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t) (&file_obj));
        }
    }
    fclose(f);
}

pid_t fork(void){
    //hprintf("ATTEMPT TO FORK?!!!\n");
#ifdef LEGACY_MODE
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
#endif
    return _fork();
    while(1){
    }
}

int execve(const char *filename, char *const argv[],
                  char *const envp[]){

#ifdef LEGACY_MODE
    /* fix to support bash out-of-the-box */
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
#endif

    hprintf("ATTEMPT TO execve?!!!\n");
    while(1){

    }
}

int execl(const char *pathname, const char *arg, ...){
    hprintf("ATTEMPT TO %s?!!!\n", __func__);
    while(1){
    }
}
       
int execlp(const char *file, const char *arg, ...){
    hprintf("ATTEMPT TO %s?!!!\n", __func__);
    while(1){
    }
}

int execle(const char *pathname, const char *arg, ...){
    hprintf("ATTEMPT TO %s?!!!\n", __func__);
    while(1){
    }    
}
     
#ifdef LEGACY_MODE
int execv(const char *pathname, char *const argv[]){
    //hprintf("ATTEMPT TO %s?!!!\n", __func__);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    while(1){
    }     
}
#endif
       
int execvp(const char *file, char *const argv[]){
    hprintf("ATTEMPT TO %s?!!!\n", __func__);
    while(1){
    }    
}
       
int execvpe(const char *file, char *const argv[],
                       char *const envp[]){
    hprintf("ATTEMPT TO %s?!!!\n", __func__);
    while(1){
    }    
}

int clearenv(void){
    hprintf("ATTEMPT TO clearenv?!!!\n");
    while(1){

    }
}

static void check_afl_auto_dict(){

    /* copy AFL autodict over to host */
    if (__afl_dictionary_len_ptr && __afl_dictionary_ptr){
        if (__afl_dictionary_len && __afl_dictionary){
            _mlock((void*)__afl_dictionary, (size_t)__afl_dictionary_len);
            kafl_dump_file_t file_obj = {0};
            file_obj.file_name_str_ptr = (uintptr_t)"afl_autodict.txt";
            file_obj.append = 1;
            file_obj.bytes = __afl_dictionary_len;
            file_obj.data_ptr = (uintptr_t)__afl_dictionary;
            kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t) (&file_obj));
            _munlock((void*)__afl_dictionary, (size_t)__afl_dictionary_len);
        }
    }
}

void nyx_init_start(void){

     /* this process is fuzzed -> set this global var to true such that 
      * all exit handlers are able to check it and raise an exit hypercall 
      */
    fuzz_process = true;
    /* reconfigure all crash handlers one more time */
    init_crash_handling();   

    static bool already_called = false;
    ASSERT(!already_called);
    already_called = true;

    dump_mappings();
    check_afl_auto_dict();

    hprintf("[init] target is an ASAN executable: %d\n", get_harness_state()->asan_executable);

    bool asan_executable = get_harness_state()->asan_executable;
    
    /*
    int (*original__libc_start_main)(int (*main) (int,char **,char **),
                    int argc,char **ubp_av,
                    void (*init) (void),
                    void (*fini)(void),
                    void (*rtld_fini)(void),
                    void (*stack_end));
    */

#ifdef LEGACY_MODE
    bool stdin_mode = true;
    char output_filename[1024];

    if(get_harness_state()->legacy_file_mode){
        stdin_mode = false;
        strncpy(output_filename, real_getenv("NYX_LEGACY_FILE_MODE"), 1024);
        hprintf("[init] output_filename: %s\n", output_filename);
    }
    
#endif 

    #if defined(REDIRECT_STDERR_TO_HPRINTF) || defined(REDIRECT_STDOUT_TO_HPRINTF)
    char buf[HPRINTF_MAX_SIZE];
    #endif
    //printf("Fnord1 !\n");

    /*
    if(!log_content){
        log_content = malloc(0x1000);
        memset(log_content, 0x00, 0x1000);
     }
    */


    remove("/tmp/target_executable");


    struct rlimit r;
    int fd, fd2 = 0;
    int pipefd[2];
    int ret = pipe(pipefd);


    #ifdef REDIRECT_STDERR_TO_HPRINTF
    int pipe_stderr_hprintf[2];
    ret = pipe(pipe_stderr_hprintf);
    #endif
    #ifdef REDIRECT_STDOUT_TO_HPRINTF
    int pipe_stdout_hprintf[2];
    ret = pipe(pipe_stdout_hprintf);
    #endif

    struct iovec iov;
    int pid;
    int status=0;
    int res = 0;
    int i;

    uint64_t memlimit_200 = 200;
    r.rlim_max = (rlim_t)(memlimit_200 << 20);
    r.rlim_cur = (rlim_t)(memlimit_200 << 20);

    //original__libc_start_main = dlsym(RTLD_NEXT,"__libc_start_main");

#ifndef STDOUT_STDERR_DEBUG
    /* check via env var if we should disable stdout/stderr -> might be useful for debug purposes */
    real_dup2(open("/dev/null", O_WRONLY), STDOUT_FILENO);
    real_dup2(open("/dev/null", O_WRONLY), STDERR_FILENO);
#endif

#ifdef LEGACY_MODE
    if(!stdin_mode){
    real_dup2(open("/dev/null", O_RDONLY), STDIN_FILENO);
    }
#endif

    if(input_buffer_size == 0){
        habort("Error: The size of the input buffer has not been specified by the host...");
    }

    //capabilites_configuration(timeout_detection, agent_tracing, ijon_tracing);

#ifndef LEGACY_MODE      
    void* payload_buffer = mmap(NULL, input_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    //void* payload_buffer = mmap((void*)NULL, input_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
#else
    kAFL_payload* payload_buffer = mmap(NULL, input_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
#endif
    _mlock(payload_buffer, (size_t)input_buffer_size);
    //hprintf("mlock done\n");
    memset(payload_buffer, 0, input_buffer_size);
    //hprintf("memset done\n");

    hprintf("[init] payload buffer is mapped at %p (size: 0x%lx)\n", payload_buffer, input_buffer_size);

    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);
    //hprintf("get payload done\n");

    //fail();

    //hprintf("payload_buffer at %p\n", payload_buffer);

    mprotect(payload_buffer, input_buffer_size, PROT_EXEC);

    kAFL_ranges* range_buffer = mmap((void*)NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(range_buffer, 0xff, 0x1000);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (uintptr_t)range_buffer);

    for(i = 0; i < 4; i++){
        if (range_buffer->enabled[i]){
            hprintf("[init] Intel PT range %d is enabled\t -> (0x"PRIx64"-0x"PRIx64")\n", i, range_buffer->ip[i], range_buffer->ip[i]+range_buffer->size[i]);
        }
    }

#if defined(__i386__)
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_32);
#elif defined(__x86_64__)
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);
#endif

    if(!asan_executable){
        //setrlimit(RLIMIT_AS, &r);
    }

    address_range_t* ar = malloc(sizeof(address_range_t));
    memset(ar, 0x0, sizeof(address_range_t));
    ar->name = "ld_preload_fuzz.so";
    calc_address_range(ar);

    if(ar->found){
        hprintf("[init] ld_preload library mapped at:\t0x%016lx-0x%016lx\n", ar->start, ar->end);
        hprintf("[init] target region                \t0x%016lx-0x%016lx (IP0)\n", ar->ip0_a, ar->ip0_b);
        hprintf("[init] library region               \t0x%016lx-0x%016lx (IP1)\n", ar->ip1_a, ar->ip1_b);
    }

    uint64_t* ranges = malloc(sizeof(uint64_t)*3);
    memset(ranges, 0x0, sizeof(uint64_t)*3);

    if(get_harness_state()->pt_auto_addr_range_a){
        ranges[0] = ar->ip0_a;
        ranges[1] = ar->ip0_b;
        //ranges[0] = 0x555550000000;
        //ranges[1] = 0x5F5550000000;

        ranges[2] = 0;
    }
    else{
        /* fix this later */
        ranges[0] = 0xFFFFFFFFFFFFF000;
        ranges[1] = 0xfffffffffffff001;
        ranges[2] = 0;
    }

    /* submit the address ranges for IPT tracing even if our target has compile-time instrumentations */
    //if(!get_harness_state()->afl_mode){
        kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)ranges);
    //}

    if(get_harness_state()->pt_auto_addr_range_b){
        ranges[0] = ar->ip1_a;
        ranges[1] = ar->ip1_b;
        ranges[2] = 1;
    }
    else{
        /* fix this later */
        ranges[0] = 0xFFFFFFFFFFFFF001;
        ranges[1] = 0xfffffffffffff002;
        ranges[2] = 1;
    }
    
    /* submit the address ranges for IPT tracing even if our target has compile-time instrumentations */
    //if(!get_harness_state()->afl_mode){
        kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uintptr_t)ranges);
    //}
    /* init stuff */
    //fptr_read = dlsym(RTLD_NEXT, "read"); 
    //fptr_getline = dlsym(RTLD_NEXT, "getline"); 
    //fprintf(stderr, "called setup()\n");
    free(ar);
    free(ranges);

#ifndef LEGACY_MODE
    vm = new_interpreter();
    vm->user_data = &vm_state;
    vm->user_data->len = 0;
    vm->user_data->data = 0;
    vm->user_data->closed = false;
#endif

    uint8_t mlock_enabled = 1;

    //hprintf("asan_executable -> %d\n", asan_executable);

    if(!asan_executable){
        if(_mlockall(MCL_CURRENT)){
            hprintf("[init ]mlockall(MCL_CURRENT) has failed!\n");
            /* dont' abort if mlockall fails */
            //kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
        }
    }

    config_handler();

    if(get_harness_state()->fast_exit_mode){
        atexit(fast_exit);
    }

#ifdef NET_FUZZ
    atexit(fast_exit);
#endif 

    //hprintf("========================================================\n");

    while(1){

/* fixme */
#ifndef NET_FUZZ
        pid = _fork();
#else
        pid = 0;
#endif

        if(!pid){
            if(!asan_executable){
                if(mlock_enabled){
                    config_handler();
                    if(_mlockall(MCL_CURRENT)){
                        hprintf("[init] mlockall(MCL_CURRENT) has failed!\n");
                        /* dont' abort if mlockall fails */
                        //kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
                    }
                }
            }

#ifndef NET_FUZZ
#ifdef LEGACY_MODE
            if(stdin_mode){
                ret = pipe(pipefd);
            }
            else{
                fd = open(output_filename, O_RDWR | O_CREAT | O_TRUNC, O_RDWR);
            }
#endif
            //mlockall(MCL_CURRENT); // | MCL_FUTURE);
#endif
            fuzzer_ready = true;

            kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);

            //debug_time();
#ifdef LEGACY_MODE
            if (stdin_mode){
                if(payload_buffer->size){
                    iov.iov_base = payload_buffer->data;
                    iov.iov_len = payload_buffer->size;
                    ret = vmsplice(pipefd[1], &iov, 1, SPLICE_F_GIFT);
                }
                real_dup2(pipefd[0],STDIN_FILENO);
                close(pipefd[1]);  
            }
            else{
                if(unlikely(write(fd, payload_buffer->data, payload_buffer->size) == -1)){
                    habort("Cannot write Nyx input to guest file -> write() failed!\n");
                }
            }
#else
            setup_interpreter(payload_buffer);
#endif

            #ifdef REDIRECT_STDERR_TO_HPRINTF
            real_dup2(pipe_stderr_hprintf[1], STDERR_FILENO);
            close(pipe_stderr_hprintf[0]);
            #endif
            #ifdef REDIRECT_STDOUT_TO_HPRINTF
            real_dup2(pipe_stdout_hprintf[1], STDOUT_FILENO);
            close(pipe_stdout_hprintf[0]);
            #endif  

            return;
        }
        else if(pid > 0){
            #ifdef REDIRECT_STDERR_TO_HPRINTF
            close(pipe_stderr_hprintf[1]);
            #endif
            #ifdef REDIRECT_STDOUT_TO_HPRINTF
            close(pipe_stdout_hprintf[1]);
            #endif          
            waitpid(pid, &status, WUNTRACED);

            if(get_harness_state()->fast_exit_mode){
                habort("Error: --fast_reload_mode is not supported in non-reload mode...");
            }
            
            if(WIFSIGNALED(status) || WEXITSTATUS(status) == ASAN_EXIT_CODE){
                kAFL_hypercall(HYPERCALL_KAFL_PANIC, 1);
            } 

            #ifdef REDIRECT_STDERR_TO_HPRINTF
            hprintf("------------STDERR-----------\n");
            while(read(pipe_stderr_hprintf[0], buf, HPRINTF_MAX_SIZE)){
                hprintf("%s", buf);
            }
            hprintf("-----------------------------\n");
            #endif 
            #ifdef REDIRECT_STDOUT_TO_HPRINTF
            hprintf("------------STDDOUT-----------\n");
            while(read(pipe_stdout_hprintf[0], buf, HPRINTF_MAX_SIZE)){
                hprintf("%s", buf);
            }
            hprintf("-----------------------------\n");
            #endif 
         
            kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
            mlock_enabled = 0;

        }
        else{
            habort("Error: fork() has failed...");
        }
    }
}

char *getenv(const char *name){

    if(get_harness_state()->afl_mode && !strcmp(name, "__AFL_SHM_ID")){
        return "5134680";
    }
    return real_getenv(name);
}

void *shmat(int shmid, const void *shmaddr, int shmflg){
    if(get_harness_state()->afl_mode && shmid == 5134680){
        capabilites_configuration(false, true, false);
        if(!get_harness_state()->net_fuzz_mode){
#ifndef LEGACY_MODE
            //nyx_init_start();
#endif
        }
        return trace_buffer;
    }

    void* (*_shmat)(int shmid, const void *shmaddr, int shmflg) = dlsym(RTLD_NEXT, "shmat"); 
    return _shmat(shmid, shmaddr, shmflg);
}

void nyx_init(void){
    capabilites_configuration(false, false, true);
    nyx_init_start();
}

int (*original_main) (int,char **, char **) = NULL;

int __main(int argc, char** argv, char** envp){

    if(get_harness_state()->afl_mode){
        capabilites_configuration(false, true, true);
    }
    if (get_harness_state()->net_fuzz_mode){
        capabilites_configuration(false, false, true);
        hprintf("Info: running in net fuzz mode!\n");
    }
    else {
        if(!get_harness_state()->delayed_init && !get_harness_state()->net_fuzz_mode){
            hprintf("Info: delayed_init mode disabled!\n");
            capabilites_configuration(false, false, true);
            //nyx_init_start();
        }    
        else{
            hprintf("Info: delayed_init mode enabled!\n");
        }
    }

#ifdef LEGACY_MODE
    nyx_init();
#endif
    return original_main(argc, argv, envp);
}

int __libc_start_main(int (*main) (int,char **,char **),
              int argc,char **ubp_av,
              void (*init) (void),
              void (*fini)(void),
              void (*rtld_fini)(void),
              void (*stack_end)) {

    int (*original__libc_start_main)(int (*main) (int,char **,char **),
        int argc,char **ubp_av,
        void (*init) (void),
        void (*fini)(void),
        void (*rtld_fini)(void),
        void (*stack_end));    

/*
#ifdef NET_FUZZ
    init_syscall_fptr();
#endif
*/
    fuzz_process = false;
    init_syscall_fptr();

    original__libc_start_main = dlsym(RTLD_NEXT,"__libc_start_main");

    /* Check if this is our target process we want to fuzz. 
     *       **Rewrite this code** 
     */
    if(strcmp(ubp_av[0], "./target_executable")){
        hprintf("Warning: argv[0] = %s\n", ubp_av[0]);
        return original__libc_start_main(main,argc,ubp_av, init,fini,rtld_fini,stack_end);
    }

    fptr_read = dlsym(RTLD_NEXT, "read"); 
    fptr_getline = dlsym(RTLD_NEXT, "getline"); 

    set_harness_state();
    init_crash_handling();

    original_main = main;

    return original__libc_start_main(__main,argc,ubp_av, init,fini,rtld_fini,stack_end);
}
