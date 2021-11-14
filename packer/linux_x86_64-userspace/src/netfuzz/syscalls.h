#pragma once

#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

void init_syscall_fptr(void);

ssize_t real_read(int fd, void* buf, size_t count);
ssize_t real_write(int fd, const void *buf, size_t count);
int real_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int real_listen(int sockfd, int backlog);
int real_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int real_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
ssize_t real_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t real_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t real_recvmsg(int sockfd, struct msghdr *msg, int flags);
int real_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int real_close(int fd);
int real_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int real_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int real_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t real_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
int real_dup(int fd);
int real_dup2(int oldfd, int newfd);
int real_dup3(int oldfd, int newfd, int flags);
int real_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int real_getc(FILE *stream);
void real__exit(int status);
ssize_t real_readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t real_writev(int fd, const struct iovec *iov, int iovcnt);
ssize_t real_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t real_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
char* real_getenv(const char *name);
int real_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int real_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
char *real_fgets(char *s, int size, FILE *stream);
int real_open(const char *pathname, int flags);
int real_ioctl(int fd, int cmd, void *argp);
