#define _GNU_SOURCE
#include <dlfcn.h>
#include "syscalls.h"
#include "nyx.h"
#include <sys/epoll.h>
#include <stdbool.h>
#include <assert.h>

typedef int (*real_listen_t)(int, int);
typedef int (*real_accept_t)(int, struct sockaddr*, socklen_t *);
typedef int (*real_accept4_t)(int, struct sockaddr*, socklen_t *, int flags);
typedef ssize_t (*real_recv_t)(int, void*, size_t, int);
typedef ssize_t (*real_recvfrom_t)(int, void*, size_t, int, struct sockaddr*, socklen_t*);
typedef ssize_t (*real_recvmsg_t)(int, struct msghdr*, int);
typedef int (*real_select_t)(int, fd_set*, fd_set*, fd_set*, struct timeval*);
typedef ssize_t (*real_read_t)(int, void*, size_t);
typedef int (*real_poll_t)(struct pollfd* , nfds_t, int);
typedef int (*real_close_t)(int);
typedef ssize_t (*real_send_t)(int, const void*, size_t, int);
typedef ssize_t (*real_write_t)(int, const void*, size_t);
typedef int (*real_epoll_ctl_t)(int, int, int, struct epoll_event*);
typedef int (*real_epoll_wait_t)(int, struct epoll_event*, int, int);
typedef int (*real_bind_t)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*real_sendto_t)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef int (*real_dup_t)(int);
typedef int (*real_dup2_t)(int, int);
typedef int (*real_dup3_t)(int, int, int);
typedef int (*real_connect_t)(int, const struct sockaddr *, socklen_t);
typedef int (*real_getc_t)(FILE*);
typedef void (*real__exit_t)(int);
typedef ssize_t (*real_readv_t)(int, const struct iovec*, int);
typedef ssize_t (*real_writev_t)(int, const struct iovec*, int);
typedef ssize_t (*real_preadv_t)(int, const struct iovec*, int, off_t);
typedef ssize_t (*real_pwritev_t)(int, const struct iovec*, int, off_t);
typedef char* (*real_getenv_t)(const char *name);
typedef int (*real_getsockname_t)(int, struct sockaddr*, socklen_t*);
typedef int (*real_getpeername_t)(int, struct sockaddr*, socklen_t*);
typedef char* (*real_fgets_t)(char*, int, FILE*);
typedef int (*real_open_t)(const char *pathname, int flags);
typedef int (*real_ioctl_t)(int fd, int cmd, void *argp);

bool initialized = false;

real_listen_t real_listen_ptr = NULL;
real_accept_t real_accept_ptr = NULL;
real_accept4_t real_accept4_ptr = NULL;
real_recv_t real_recv_ptr = NULL;
real_recvfrom_t real_recvfrom_ptr = NULL;
real_recvmsg_t real_recvmsg_ptr = NULL;
real_select_t real_select_ptr = NULL;
real_read_t real_read_ptr = NULL;
real_poll_t real_poll_ptr = NULL;
real_close_t real_close_ptr = NULL;
real_send_t real_send_ptr = NULL;
real_write_t real_write_ptr = NULL;
real_epoll_ctl_t real_epoll_ctl_ptr = NULL;
real_epoll_wait_t real_epoll_wait_ptr = NULL;
real_bind_t real_bind_ptr = NULL;
real_sendto_t real_sendto_ptr = NULL;
real_dup_t real_dup_ptr = NULL;
real_dup2_t real_dup2_ptr = NULL;
real_dup3_t real_dup3_ptr = NULL;
real_connect_t real_connect_ptr = NULL;
real_getc_t real_getc_ptr = NULL;
real__exit_t real__exit_ptr = NULL;
real_readv_t real_readv_ptr = NULL;
real_writev_t real_writev_ptr = NULL;
real_preadv_t real_preadv_ptr = NULL;
real_pwritev_t real_pwritev_ptr = NULL;
real_getenv_t real_getenv_ptr = NULL;
real_getsockname_t real_getsockname_ptr = NULL;
real_getpeername_t real_getpeername_ptr = NULL;
real_fgets_t real_fgets_ptr = NULL;
real_open_t real_open_ptr = NULL;
real_ioctl_t real_ioctl_ptr = NULL;


void init_syscall_fptr(void){

  if(initialized){
    return;
  }
  //assert(!initialized); /* only called once */

  real_listen_ptr = (real_listen_t)dlsym(RTLD_NEXT, "listen");
  real_accept_ptr = (real_accept_t)dlsym(RTLD_NEXT, "accept");
  real_accept4_ptr = (real_accept4_t)dlsym(RTLD_NEXT, "accept4");
  real_recv_ptr = (real_recv_t)dlsym(RTLD_NEXT, "recv");
  real_recvfrom_ptr = (real_recvfrom_t)dlsym(RTLD_NEXT, "recvfrom");
  real_recvmsg_ptr = (real_recvmsg_t)dlsym(RTLD_NEXT, "recvmsg");
  real_select_ptr = (real_select_t)dlsym(RTLD_NEXT, "select");
  real_read_ptr = (real_read_t)dlsym(RTLD_NEXT, "read");
  real_poll_ptr = (real_poll_t)dlsym(RTLD_NEXT, "poll");
  real_close_ptr = (real_close_t)dlsym(RTLD_NEXT, "close");
  real_send_ptr = (real_send_t)dlsym(RTLD_NEXT, "send");
  real_write_ptr = (real_write_t)dlsym(RTLD_NEXT, "write");
  real_epoll_ctl_ptr = (real_epoll_ctl_t)dlsym(RTLD_NEXT, "epoll_ctl");
  real_epoll_wait_ptr = (real_epoll_wait_t)dlsym(RTLD_NEXT, "epoll_wait");
  real_bind_ptr = (real_bind_t)dlsym(RTLD_NEXT, "bind");
  real_sendto_ptr = (real_sendto_t)dlsym(RTLD_NEXT, "sendto");
  real_dup_ptr = (real_dup_t)dlsym(RTLD_NEXT, "dup");
  real_dup2_ptr = (real_dup2_t)dlsym(RTLD_NEXT, "dup2");
  real_dup3_ptr = (real_dup3_t)dlsym(RTLD_NEXT, "dup3");
  real_connect_ptr = (real_connect_t)dlsym(RTLD_NEXT, "connect");
  real_getc_ptr = (real_getc_t)dlsym(RTLD_NEXT, "getc");
  real__exit_ptr = (real__exit_t)dlsym(RTLD_NEXT, "_exit");
  real_readv_ptr = (real_readv_t)dlsym(RTLD_NEXT, "readv");
  real_writev_ptr = (real_writev_t)dlsym(RTLD_NEXT, "writev");
  real_preadv_ptr = (real_preadv_t)dlsym(RTLD_NEXT, "preadv");
  real_pwritev_ptr = (real_pwritev_t)dlsym(RTLD_NEXT, "pwritev");
  real_getenv_ptr = (real_getenv_t)dlsym(RTLD_NEXT, "getenv");
  real_getsockname_ptr = (real_getsockname_t)dlsym(RTLD_NEXT, "getsockname");
  real_getpeername_ptr = (real_getpeername_t)dlsym(RTLD_NEXT, "getpeername");
  real_fgets_ptr = (real_fgets_t)dlsym(RTLD_NEXT, "fgets");
  real_open_ptr = (real_open_t)dlsym(RTLD_NEXT, "open");
  real_ioctl_ptr = (real_ioctl_t)dlsym(RTLD_NEXT, "ioctl");

  assert(real_listen_ptr);
  assert(real_accept_ptr);
  assert(real_accept4_ptr);
  assert(real_recv_ptr);
  assert(real_recvfrom_ptr);
  assert(real_recvmsg_ptr);
  assert(real_select_ptr);
  assert(real_read_ptr);
  assert(real_poll_ptr);
  assert(real_close_ptr);
  assert(real_send_ptr);
  assert(real_write_ptr);
  assert(real_epoll_ctl_ptr);
  assert(real_epoll_wait_ptr);
  assert(real_bind_ptr);
  assert(real_sendto_ptr);
  assert(real_dup_ptr);
  assert(real_dup2_ptr);
  assert(real_dup3_ptr);
  assert(real_connect_ptr);
  assert(real_getc_ptr);
  assert(real__exit_ptr);
  assert(real_readv_ptr);
  assert(real_writev_ptr);
  assert(real_preadv_ptr);
  assert(real_pwritev_ptr);
  assert(real_getenv_ptr);
  assert(real_getsockname_ptr);
  assert(real_getpeername_ptr);
  assert(real_open_ptr);
  assert(real_ioctl_ptr);

  initialized = true;

}

ssize_t real_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){
  assert(real_sendto_ptr);
  return real_sendto_ptr(sockfd, buf, len, flags, dest_addr, addrlen);                
}

int real_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event){
  assert(real_epoll_ctl_ptr);
  return real_epoll_ctl_ptr(epfd, op, fd, event);   
}

int real_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout){
  assert(real_epoll_wait_ptr);
  return real_epoll_wait_ptr(epfd, events, maxevents, timeout);
}

ssize_t real_read(int fd, void* buf, size_t count){
  assert(real_read_ptr);
  return real_read_ptr(fd, buf, count);
}

int real_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout){
  assert(real_select_ptr);
  return real_select_ptr(nfds, readfds, writefds, exceptfds, timeout);
}

int real_listen(int sockfd, int backlog) {
  assert(real_listen_ptr);
  return real_listen_ptr(sockfd, backlog);
}

int real_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  assert(real_accept_ptr);
  return real_accept_ptr(sockfd, addr, addrlen);
}

int real_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags){
  assert(real_accept4_ptr);
  return real_accept4_ptr(sockfd, addr, addrlen, flags);
}

ssize_t real_recv(int sockfd, void *buf, size_t len, int flags){
  assert(real_recv_ptr);
  return real_recv_ptr(sockfd, buf, len, flags);
}

ssize_t real_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
  assert(real_recvfrom_ptr);
  return real_recvfrom_ptr(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t real_recvmsg(int sockfd, struct msghdr *msg, int flags){
  assert(real_recvmsg_ptr);
  return real_recvmsg_ptr(sockfd, msg, flags);
}

int real_poll(struct pollfd *fds, nfds_t nfds, int timeout){
  assert(real_poll_ptr);
  return real_poll_ptr(fds, nfds, timeout);
}

int real_close(int fd){
  assert(real_close_ptr);
  return real_close_ptr(fd);
}

ssize_t real_send(int sockfd, const void *buf, size_t len, int flags){
  assert(real_send_ptr);
  return real_send_ptr(sockfd, buf, len, flags);
}

ssize_t real_write(int fd, const void *buf, size_t count){
  assert(real_write_ptr);
  return real_write_ptr(fd, buf, count);
}

int real_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
  assert(real_bind_ptr);
  return real_bind_ptr(sockfd, addr, addrlen);
}

int real_dup(int fd){
  assert(real_dup_ptr);
  return real_dup_ptr(fd);
}

int real_dup2(int oldfd, int newfd){
  assert(real_dup2_ptr);
  return real_dup2_ptr(oldfd, newfd);
}

int real_dup3(int oldfd, int newfd, int flags){
  assert(real_dup3_ptr);
  return real_dup3_ptr(oldfd, newfd, flags);
}

int real_getc(FILE *stream){
  assert(real_getc_ptr);
  return real_getc_ptr(stream);
}

int real_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
  assert(real_connect_ptr);
  return real_connect_ptr(sockfd, addr, addrlen);
}

void real__exit(int status){
  assert(real__exit_ptr);
  return real__exit_ptr(status);
}


ssize_t real_readv(int fd, const struct iovec *iov, int iovcnt){
  assert(real_readv_ptr);
  return real_readv_ptr(fd, iov, iovcnt);
}

ssize_t real_writev(int fd, const struct iovec *iov, int iovcnt){
  assert(real_write_ptr);
  return real_write_ptr(fd, iov, iovcnt);
}

ssize_t real_preadv(int fd, const struct iovec *iov, int iovcnt,
               off_t offset){
  assert(real_preadv_ptr);
  return real_preadv_ptr(fd, iov, iovcnt, offset);
}

ssize_t real_pwritev(int fd, const struct iovec *iov, int iovcnt,
                off_t offset){
  assert(real_pwritev_ptr);
  return real_pwritev_ptr(fd, iov, iovcnt, offset);
}

char* real_getenv(const char *name){
  /* getenv() might be called before main() */
  if(real_getenv_ptr){
    return real_getenv_ptr(name);
  }
  else{
   return ((real_getenv_t)dlsym(RTLD_NEXT, "getenv"))(name);
  }
}

int real_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  assert(real_getsockname_ptr);
  return real_getsockname_ptr(sockfd, addr, addrlen);
}

int real_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  assert(real_getpeername_ptr);
  return real_getpeername_ptr(sockfd, addr, addrlen);
}

char *real_fgets(char *s, int size, FILE *stream){
  assert(real_fgets_ptr);
  return real_fgets_ptr(s, size, stream);
}

int real_open(const char *pathname, int flags){
  assert(real_open_ptr);
  return real_open_ptr(pathname, flags);
}

int real_ioctl(int fd, int cmd, void *argp){
  assert(real_ioctl_ptr);
  return real_ioctl_ptr(fd, cmd, argp);
}
