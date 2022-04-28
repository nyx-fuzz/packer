#define _GNU_SOURCE

#include <signal.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <execinfo.h>
#include <stdbool.h>
#include <sys/stat.h> 

//#include <ucontext.h>
#include "nyx.h"
#include "misc/crash_handler.h"
#include "misc/harness_state.h"

static char* log_content = NULL;
static bool ready = false;

void handle_asan(void);

static bool file_exists (char *filename) {
  struct stat   buffer;   
  return (stat (filename, &buffer) == 0);
}

static bool check_early_env(void){
    return ("echo $NYX_ASAN_EXECUTABLE | grep TRUE");
}

void init_crash_handling(void){
    //hprintf("======== CALLED: %s\n", __func__);
    if(!log_content){
        log_content = malloc(0x1000);
        memset(log_content, 0x00, 0x1000);
    }
    ready = true;
    config_handler();
}

static void fault_handler(int signo, siginfo_t *info, void *extra){
    ucontext_t *context = (ucontext_t *)extra;
    //kafl_backtrace(info->si_signo);
#if defined(__i386__)
    uint64_t reason = 0x8000000000000000ULL | context->uc_mcontext.gregs[REG_EIP] | ( (uint64_t)info->si_signo << 47);
#else
    uint64_t reason = 0x8000000000000000ULL | context->uc_mcontext.gregs[REG_RIP] | ( (uint64_t)info->si_signo << 47);
#endif
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, reason);
}

static void fault_handler_asan(int signo, siginfo_t *info, void *extra){
    handle_asan();
    ucontext_t *context = (ucontext_t *)extra;
    //kafl_backtrace(info->si_signo);
#if defined(__i386__)
    uint64_t reason = 0x8000000000000000ULL | context->uc_mcontext.gregs[REG_EIP] | ( (uint64_t)info->si_signo << 47);
#else
    uint64_t reason = 0x8000000000000000ULL | context->uc_mcontext.gregs[REG_RIP] | ( (uint64_t)info->si_signo << 47);
#endif
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, reason);
}


static void set_handler(void (*handler)(int,siginfo_t *,void *)){
    //hprintf("%s\n", __func__);
    struct sigaction action;
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = handler;

    int (*new_sigaction)(int signum, const struct sigaction *act, struct sigaction *oldact);
    new_sigaction = dlsym(RTLD_NEXT, "sigaction");
        
    if(!get_harness_state()->asan_executable){
        if (new_sigaction(SIGSEGV, &action, NULL) == -1) {
            hprintf("sigsegv: sigaction");
            _exit(1);
        }
        if (new_sigaction(SIGFPE, &action, NULL) == -1) {
            hprintf("sigfpe: sigaction");
            _exit(1);
        }
        if (new_sigaction(SIGBUS, &action, NULL) == -1) {
            hprintf("sigbus: sigaction");
            _exit(1);
        }
    }
    
    if (new_sigaction(SIGILL, &action, NULL) == -1) {
        hprintf("sigill: sigaction");
        _exit(1);
    }
    
    if (new_sigaction(SIGABRT, &action, NULL) == -1) {
        hprintf("sigabrt: sigaction");
        _exit(1);
    }
    if (new_sigaction(SIGIOT, &action, NULL) == -1) {
        hprintf("sigiot: sigaction");
        _exit(1);
    }
    if (new_sigaction(SIGTRAP, &action, NULL) == -1) {
        hprintf("sigiot: sigaction");
        _exit(1);
    }
    if (new_sigaction(SIGSYS, &action, NULL) == -1) {
        hprintf("sigsys: sigaction");
        _exit(1);
    }
    hprintf("[!] all signal handlers are hooked!\n");
    //kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, 0);
}

void config_handler(void){
    if(!get_harness_state()->asan_executable){
        set_handler(fault_handler);
    } 
    else{
        set_handler(fault_handler_asan);
    }
    signal(SIGPIPE, SIG_IGN);
}


/* todo: allow sigaction for SIGSEGV once (allow ASAN to set a sighandler) */ 
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact){
    int (*new_sigaction)(int signum, const struct sigaction *act, struct sigaction *oldact);

    if(ready){
        switch(signum){
            /* forbidden signals */
            case SIGFPE:
            case SIGILL:
            case SIGBUS:
            case SIGABRT:
            case SIGTRAP:
            case SIGSYS:            
            case SIGSEGV:
                //hprintf("Target attempts to install own SIG: %d handler\n", signum);
                return 0;
            default:
                //hprintf("===> %s: SIG: %d\n", __func__, signum);
                new_sigaction = dlsym(RTLD_NEXT, "sigaction");
                return new_sigaction(signum, act, oldact);
        }
    }
    else{
        //hprintf("===> %s: SIG: %d\n", __func__, signum);
        new_sigaction = dlsym(RTLD_NEXT, "sigaction");
        return new_sigaction(signum, act, oldact);
    }
}

void handle_asan(void){
    char* log_file_path = NULL;
    char* log_content = NULL;
    int ignored;

    if(-1 == asprintf(&log_file_path, "/tmp/data.log.%d", getpid())) {
        kAFL_hypercall(HYPERCALL_KAFL_PANIC, 0);
    }

    FILE* f = fopen(log_file_path, "r");

    if(f){
        log_content = malloc(0x1000);
        memset(log_content, 0x00, 0x1000);
        ignored = fread(log_content, 0x1000-1, 1, f);
        fclose(f);
        printf("%s\n", log_content);

        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)log_content);
    }
}

void __assert(const char *func, const char *file, int line, const char *failedexpr){
        sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: assert: %s %s %d: %s\n", func, file, line, failedexpr);
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)log_content);
}

void _abort(void){
        handle_asan();
        sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: abort called: %p\n", __builtin_return_address(0));
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)log_content);
        while(1){}
}

void abort(void){
        handle_asan();
        sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: abort called: %p\n", __builtin_return_address(0));
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)log_content);
        while(1){}
}

void __abort(void){
        handle_asan();
        sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: abort called: %p\n", __builtin_return_address(0));
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)log_content);
        while(1){}
}

void __assert_fail (const char *__assertion, const char *__file, unsigned int __line, const char *__function){
        sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: assert: %s %s %d: %s\n", __function, __file, __line, __assertion);
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)log_content);
}

void __assert_perror_fail (int __errnum, const char *__file, unsigned int __line, const char *__function){
    sprintf(log_content, "HYPERCALL_KAFL_PANIC_EXTENDED: assert: %s %s %d: %d\n", __function, __file, __line, __errnum);
        kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)log_content);
}


#define BT_BUF_SIZE 100

void kafl_backtrace(int signal){

    int fd[2];
    int ignored;

    char tmp[512];
    void *buffer[BT_BUF_SIZE];
    int nptrs = 0;
    int j;
    int offset = 0;

    int bytes_read = 0;

    ignored = pipe(fd);

    nptrs = backtrace(buffer, BT_BUF_SIZE);
    //hprintf("backtrace() returned %d addresses\n", nptrs);

    
    backtrace_symbols_fd(buffer, nptrs, fd[1]);
    close(fd[1]);
    
    
/*
    char **strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        //perror("backtrace_symbols");
        //hprintf("backtrace_symbols failed!\n");
        return;
        //exit(EXIT_FAILURE);
    }
*/    

    offset += sprintf(log_content+offset, "HYPERCALL_KAFL_PANIC_EXTENDED: %s - addresses: %d (signal:%d)\n", __func__, nptrs, signal);

    bytes_read = read(fd[0], tmp, 511);
    //hprintf("bytes_read1: %d\n", bytes_read);
    while(bytes_read != 0){
        tmp[bytes_read] = 0;
        offset += sprintf(log_content+offset, "%s\n", tmp);
        bytes_read = read(fd[0], tmp, 511);
        //hprintf("bytes_read2: %d\n", bytes_read);
    }
    
    /*
    for (j = 0; j < nptrs; j++){
        offset += sprintf(log_content+offset, "%s\n", strings[j]);
        //hprintf("%s\n", strings[j]);
    }
    */

    kAFL_hypercall(HYPERCALL_KAFL_PANIC_EXTENDED, (uintptr_t)log_content);

    //free(strings);
}


void fail(void){
    void* a= NULL;
    *((char*)a) = 'a';
}
