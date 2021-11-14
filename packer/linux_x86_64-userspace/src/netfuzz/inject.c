#define _GNU_SOURCE

#include <string.h>
#include <dlfcn.h>
//#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdbool.h>
#include <assert.h>
#include <poll.h>
#include <unistd.h>

#include "syscalls.h"
#include "socket_cache.h"

#include "nyx.h"
#include <errno.h>

#include <time.h>
#include <sys/epoll.h>

#include "misc/harness_state.h"

//#define UDP_MODE

#ifdef UDP_MODE
bool valid_port(uint16_t port){

#ifdef IGNORE_PORT
	return port != IGNORE_PORT;
#else
	return true;
#endif
}
#endif

extern void nyx_init_start(void);

__attribute__ ((noreturn)) static void not_implemented(const char* func) {
	hprintf("NOT IMPLEMENTED <%s>\n", func);
	kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, (uint64_t)func);
	__builtin_unreachable();
}

static void nyx_assert(bool exp, const char* func) {
	if(!exp){
		hprintf("NYX ASSERT <%s>\n", func);
		kAFL_hypercall(HYPERCALL_KAFL_USER_ABORT, (uint64_t)func);
		__builtin_unreachable();
	}
	
}

/* TODO: eliminate sleep & usleep und bla */


//#define TARGET_PORT 5353
//#define TARGET_PORT 5158
//#define TARGET_PORT 8000

//#define DEBUG_MODE

#ifdef DEBUG_MODE
#define DEBUG(f_, ...) hprintf((f_), ##__VA_ARGS__)
#else
#define DEBUG(f_, ...) 
#endif

//extern interpreter_t* vm;

bool is_target_port(uint16_t port){
	//nyx_assert(get_harness_state()->nyx_net_port != 0, __func__);
	//hprintf("%s -> %d vs %d\n", __func__, port, get_harness_state()->nyx_net_port);

	if (port == get_harness_state()->nyx_net_port){
		return true;
	}
	else{
		return false;
	}
}

extern ssize_t call_vm(void *data, size_t max_size, bool return_pkt_size, bool disable_dump_mode);
extern void hprintf_payload(char* data, size_t len);

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
    hprintf("Time: %s - TSC: %lx\n", buffer, bench_start());
}




static inline void init_nyx(void){
	static bool init_done = false;
	if(!init_done){
		DEBUG("%s: init_done = false\n", __func__);
		nyx_init_start();
		init_done = true;
	}

}


unsigned int sleep(unsigned int seconds){
	DEBUG("%s: %u\n", __func__, seconds);
	// nope
	return 0;
}


int usleep(useconds_t usec){
	DEBUG("%s: %u\n", __func__, usec);
	/* nope */
	return 0;
}

/* special handler for fgets and gets */
char* handle_next_packet_s(int client_socket, char* s, int size){
	if(client_socket != -1){

		DEBUG("%s: %p %d\n", __func__, s, size);


		for(int i = 0; i < size-1; i++){

			DEBUG("%s -> %d call_vm\n", __func__, i);
			ssize_t ret = call_vm(s+i, 1, false, true);
			DEBUG("%s -> %d call_vm got %d\n", __func__, i, (uint8_t)s[i]);

			if(ret == -1){
				DEBUG("%s: returned -1\n", __func__);
				/* at this point our interpreter is out of data -> terminate */
				kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
			} 

			if(s[i] == '\n'){

				hprintf_payload(s, i+1);

				s[i+1] = 0;
				return s;
			}
		}
		
		hprintf_payload(s, size);
		s[size-1] = 0;
		return s;
	}
	return NULL;
}


int handle_next_packet(int client_socket, void* buf, size_t len, bool return_pkt_size){
	if(client_socket != -1){
		DEBUG("%s: fd: %d buf: %p size: %d, rps: %d\n", __func__, client_socket, buf, len, return_pkt_size);
		ssize_t data_len = call_vm(buf, len, return_pkt_size, false);

		if(data_len == -1){
			DEBUG("%s: returned -1\n", __func__);
			/* at this point our interpreter is out of data -> terminate */
			kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
		}
		return data_len;
	}
	return -1;
}

int handle_next_packet_iovec(int client_socket, const struct iovec *iov, int iovcnt, bool return_pkt_size){
	#define PACKET_BUFFER_SIZE (1<<14)
  static char data_buffer[PACKET_BUFFER_SIZE];

	uint64_t len = 0;
	for(int i = 0; i < iovcnt; i++){
		len += iov[i].iov_len;
	}

	if(client_socket != -1){
		DEBUG("%s: fd: %d <IOVEC> size: %d, rps: %d\n", __func__, client_socket, len, return_pkt_size);
		ssize_t data_len = call_vm(data_buffer, len, return_pkt_size, false);

		if(data_len == -1){
			DEBUG("%s: returned -1\n", __func__);
			/* at this point our interpreter is out of data -> terminate */
			kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
		}

		uint64_t remaining_bytes = data_len;
		uint64_t offset = 0;
		/* copy data back into iovec */
		for(int i = 0; i < iovcnt; i++){

			if(remaining_bytes <= iov[i].iov_len){
				memcpy(iov[i].iov_base, data_buffer+offset, remaining_bytes);
				break;
			}
			else{
				memcpy(iov[i].iov_base, data_buffer+offset, iov[i].iov_len);
				remaining_bytes -= iov[i].iov_len;
				offset += iov[i].iov_len;
			}
		}
		return data_len;
	}
	return -1;
}

int shutdown(int sockfd, int how){
	//hprintf("shutdown\n");
	return close(sockfd);
	//not_implemented(__func__);
}

int ioctl(int fd, int cmd, void *argp){
	if(server_socket_exists(fd)){
		return 0;
	}
	return real_ioctl(fd, cmd, argp);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt){
	DEBUG("%s --> %d\n", __func__, fd);
	if(server_socket_exists(fd)){
		init_nyx();
		int ret = handle_next_packet_iovec(fd, iov, iovcnt, false);
		//hprintf("%s -> %d\n", __func__, ret);
		return ret;
	}
	return real_readv(fd, iov, iovcnt);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt){
	DEBUG("%s --> %d\n", __func__, fd);
	if(server_socket_exists(fd)){
		//not_implemented(__func__);
		ssize_t len = 0;
		for(int i = 0; i < iovcnt; i++){
			len += iov[i].iov_len;
		}
		return len;
	}
	return real_writev(fd, iov, iovcnt);
}

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt,
               off_t offset){
	DEBUG("%s --> %d\n", __func__, fd);
	if(server_socket_exists(fd)){
		not_implemented(__func__);
	}
	return real_preadv(fd, iov, iovcnt, offset);
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt,
                off_t offset){
	DEBUG("%s --> %d\n", __func__, fd);
	if(server_socket_exists(fd)){
		not_implemented(__func__);
	}
	return real_pwritev(fd, iov, iovcnt, offset);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags){

	DEBUG("%s --> %d\n", __func__, sockfd);
	if(server_socket_exists(sockfd)){
		DEBUG("%s: sockfd: %d\n", __func__, sockfd);
		//hprintf("%s: %s %ld", __func__, buf, len);
		return len;
	}

	return real_send(sockfd, buf, len, flags);
}

ssize_t write(int fd, const void *buf, size_t count){
	DEBUG("%s --> %d %d\n", __func__, fd, count);
	if(server_socket_exists(fd)){
		DEBUG("%s: %p %ld\n", __func__, buf, count);
		return count;
	}

	return real_write(fd, buf, count);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen){
	DEBUG("%s --> %d\n", __func__, sockfd);
#ifdef UDP_MODE
	if(server_socket_exists(sockfd) && valid_port(ntohs(((struct sockaddr_in*)dest_addr)->sin_port))){
#else
	if(server_socket_exists(sockfd)){
#endif
		DEBUG("%s: sockfd: %d (%p %lx)\n", __func__, sockfd, buf, len);
		//hprintf("%s returning: %d\n", __func__, len);
		return len;
	}
	return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t read(int fd, void *buf, size_t count){
	//printf("==== %s ==== %d\n", __func__, count);
	//int client_socket = server_socket_to_client_socket(fd);
	//if(client_socket != -1){
	DEBUG("%s --> %d\n", __func__, fd);

	if(server_socket_exists(fd)){
#ifndef NET_STANDALONE
		init_nyx();
		return handle_next_packet(fd, buf, count, false);
#endif
		//hprintf("%s: not implemented\n", __func__);
		//exit(0);
		//DEBUG("%s %d (%d)\n", __func__, fd, client_socket);
		//write_trash(client_socket, buf, count);
	}
	return real_read(fd, buf, count);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags){
	int ret = 0;
	//int client_socket = server_socket_to_client_socket(sockfd);
	//if(client_socket != -1){
	DEBUG("%s --> %d\n", __func__, sockfd);

	if(server_socket_exists(sockfd)){
#ifndef NET_STANDALONE
		init_nyx();
		return handle_next_packet(sockfd, buf, len, false);
#endif

		//hprintf("%s: not implemented\n", __func__);
		//exit(0);
		//ret = send_trash(client_socket);
		//memcpy(buf, "GET /mod_expire.dll HTTP/1.0\r\n\r", 31);
		//ret = 32;
		//DEBUG("%s %d (%d) %d => %d\n", __func__, sockfd, client_socket, len, ret);
		//return ret;
	}
	ret = real_recv(sockfd, buf, len, flags);
	//if(client_socket != -1){
		//hprintf("%s: %d\n", __func__, ret);
	//}
	return ret;
}

static bool data_avaliable(int fd){
  fd_set set;
  struct timeval timeout;
  FD_ZERO (&set);
  FD_SET (fd, &set);
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  return real_select(FD_SETSIZE, &set, NULL, NULL, &timeout) == 1;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen){
	//int client_socket = server_socket_to_client_socket(sockfd);
	//if(client_socket != -1){
	DEBUG("%s --> %d\n", __func__, sockfd);

	if(server_socket_exists(sockfd)){
#if defined(UDP_MODE) && defined(IGNORE_PORT)
		if(data_avaliable(sockfd)){
			ssize_t ret = real_recvfrom(sockfd, buf, len, flags|MSG_DONTWAIT, src_addr, addrlen);
			if(ret != -1){
				DEBUG("%s ret=%d\n", __func__, ret);
				return ret;
			}
		}
#endif
#ifndef NET_STANDALONE
		static int i= 0;
		init_nyx();
		//DEBUG("%s %d (%d) [%d]\n", __func__, sockfd, client_socket, i++);
		//send_trash(client_socket);



		size_t ret =  handle_next_packet(sockfd, buf, len, flags & MSG_TRUNC);

		/* in case of UDP -> emulate src_addr (**I'm going to hell for this**) */
		/* TODO: check if socket type is DGRAM */
		if(src_addr != NULL){
			struct sockaddr_in* tmp = (struct sockaddr_in*) src_addr;
			tmp->sin_family = AF_INET;
#ifdef CLIENT_UDP_PORT
			tmp->sin_port = htons(CLIENT_UDP_PORT);
#else
			tmp->sin_port = htons(50000);
#endif
			tmp->sin_addr.s_addr = htonl(0x7F000001); /* 127.0.0.1 */
			*addrlen = sizeof(struct sockaddr_in);
		}

		//hprintf("%s returning: %d\n", __func__, ret);
		return ret;
#endif
	}
	ssize_t ret = real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	DEBUG("%s ret=%d\n", __func__, ret);
	/*
	if (ret < 0){

		DEBUG("%s error: %s", __func__, strerror(errno));
		while(1){

		}
	}
	*/
	return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags){
	//int client_socket = server_socket_to_client_socket(sockfd);
	//if(client_socket != -1){

	DEBUG("%s --> %d\n", __func__, sockfd);

	if(server_socket_exists(sockfd)){
	
		//hprintf("%s: not implemented\n", __func__);
		exit(0);
		//DEBUG("%s %d (%d)\n", __func__, sockfd, client_socket);
		//send_trash(client_socket);
	}
	return real_recvmsg(sockfd, msg, flags);
}

int getc(FILE *stream){
	int fd = fileno(stream);
	if(fd != -1 && server_socket_exists(fd)){


		char buf = 0;

		init_nyx();
		//return 'a';
		int ret = handle_next_packet(fd, &buf, 1, false);

		if (ret == -1){
			/* EOF */
			DEBUG("==> EOF\n");
			return -1;
		}
		DEBUG("GETC callend -> <%c>!\n", buf);
		return (int)buf;
	}

	return real_getc(stream);
}

char *fgets(char *s, int size, FILE *stream){
	int fd = fileno(stream);
	if(fd != -1 && server_socket_exists(fd)){

		init_nyx();
		return handle_next_packet_s(fd, s, size);
	}
	return real_fgets(s, size, stream);
}

/* simple workaround to read passwords from stdin */
char *getpass(const char *prompt){
    char *line = NULL;
    size_t len = 0;
    ssize_t read = 0;
    //puts(prompt);
    read = getline(&line, &len, stdin);
    if (read == -1){
    	return NULL;
    }
    line[read-1] = 0;
		//hprintf("PASS -> %s\n", line);
    return line;
}

int dup(int oldfd){
	if(server_socket_exists(oldfd)){

		DEBUG("DUP callend!\n");

		int ret = real_dup(oldfd);

		if(ret != -1){
			/* close newfd first if it is already registered in our socket cache */
			//disable_connection_by_server_socket(ret);
			/* bind newfd to our port */
			int port = server_socket_to_port(oldfd);

			if(port == -1){
				hprintf("FAIL in %s!", __func__);
			}
			assert(port != -1);
			set_server_socket_to_connection(port, ret);

			DEBUG("DUP -> oldfd: %d is now mapped to fd: %d!\n", oldfd, ret);
		}

		return ret; 
	}
	return real_dup(oldfd);

/*

	if(server_socket_exists(oldfd)){
		DEBUG("DUP!\n");
		hprintf("DUP!\n");
		while(1){}
	}

	return real_dup(oldfd);
*/
}

int dup2(int oldfd, int newfd){
	if(server_socket_exists(oldfd)){

		//close(newfd);

		
		DEBUG("DUP2 callend!\n");

		int ret = real_dup2(oldfd, newfd);

		if(ret != -1){
			/* close newfd first if it is already registered in our socket cache */
			disable_connection_by_server_socket(ret);
			/* bind newfd to our port */
			int port = server_socket_to_port(oldfd);

			if(port == -1){
				hprintf("FAIL in %s!", __func__);
			}
			assert(port != -1);
			set_server_socket_to_connection(port, ret);

			DEBUG("DUP2 -> oldfd: %d is now mapped to newfd: %d!\n", oldfd, ret);
		}

		return ret; 


		DEBUG("DUP2!\n");
		hprintf("DUP2!\n");

		while(1){}
	}

	return real_dup2(oldfd, newfd);
}

int dup3(int oldfd, int newfd, int flags){
	if(server_socket_exists(oldfd)){
		DEBUG("DUP3!\n");
		hprintf("DUP3!\n");

		while(1){}
	}

	return real_dup3(oldfd, newfd, flags);
}

int close(int fd){
	//DEBUG("%s: %d\n", __func__, fd);

	if(server_socket_exists(fd)){
		DEBUG("%s: %d\n", __func__, fd);

		disable_connection_by_server_socket(fd);
		DEBUG("%s: %d => %d\n", __func__, fd, get_active_connections() );

		/* broken ? */
		if(get_active_connections() == 0){
			DEBUG("RELEASE!\n");
			//while(1){}
			//	
			//}
			//printf("=============\n");
			//do_heap_stuff();
			kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
			//exit(0);
		}

	}
	return real_close(fd);
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout){


	/* disable timeouts */
	struct timeval timeout_new;
	timeout_new.tv_sec = 0;
	timeout_new.tv_usec = 0;

	fd_set old_readfds;

	if(readfds){
		memcpy(&old_readfds, readfds, sizeof(fd_set));
	}

	int ret = real_select(nfds, readfds, writefds, exceptfds, &timeout_new);

	//timeout_new.tv_sec = 4;
	//timeout_new.tv_usec = 100;

	if(get_active_connections() && readfds){
		//hprintf("%s\n", __func__);

		return ret + set_select_fds(readfds, &old_readfds); 
		//return 1; /* fix this dude */

			/* todo update ret? */
	}
		
	return ret;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout){
	DEBUG("%s: %d\n", __func__, nfds);

	/* todo: more features ? */
	for(int i = 0; i < nfds; i++){
		fds[i].revents = 0;
		if(((fds[i].events & POLLIN) || (fds[i].events & POLLOUT)) && server_socket_exists(fds[i].fd)){
			fds[i].revents = ((fds[i].events & POLLIN) | (fds[i].events & POLLOUT));
			//printf("%s: RETURNING -> %d\n", __func__, fds[i].fd);
			return 1;
		}
	}
	DEBUG("%s: DEFAULT %d -> timeout: %d\n", __func__, nfds, timeout);

	int ret = real_poll(fds, nfds, 0);
	return ret;
}

extern void foo(void);

int connect_to_server(const char* ip, int port){
	int socket_desc;
	struct sockaddr_in server; 

	DEBUG("%s enter\n", __func__);

#ifdef TARGET_PORT
	if(port != TARGET_PORT){
		return 0;
	}
#endif

	//hprintf("%s: %s %d\n", __func__, ip, port);
	//exit(0);

	if(!is_target_port(port)){
		return 0;
	}
	
				
	/* remove this line and the guest TCP stack will break => FIX ME */			
	//init_nyx();


	DEBUG("%s enter2\n", __func__);

	//Create socket
	//printf("%s: create socket...\n", __func__);

#ifdef UDP_MODE
	socket_desc = socket(AF_INET , SOCK_DGRAM , 0);
#else
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
#endif
	if (socket_desc == -1)
	{
		DEBUG("Could not create socket");
		exit(-1);
	}
		
	server.sin_addr.s_addr = inet_addr(ip); //inet_addr(ip); //"74.125.235.20");
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	//Connect to remote server
	//printf("%s: connect to socket...\n", __func__);
	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
	{
		DEBUG("connect error %s", strerror(errno));
		exit(-1);
	}

	//		init_nyx();


	assert(set_client_socket_to_connection(port, socket_desc));

	
	//send(socket_desc, "ABCD", 5, 0);

	//puts("Connected");
	return 0;


}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags){
	//hprintf("============ %s ===========\n", __func__);
	//sleep(1);


	int ret = real_accept4(sockfd, addr, addrlen, flags);

	struct sockaddr_in tmp_addr;
	int len = sizeof(struct sockaddr);
	if(ret != -1 && getsockname(sockfd, (struct sockaddr *) &tmp_addr, (void*)&len) != -1){
		if(ret != -1 && is_target_port(ntohs(tmp_addr.sin_port))) {
			//hprintf("%s %d %d\n", __func__, tmp_addr.sin_port, ret);
			assert(set_server_socket_to_connection(ntohs(tmp_addr.sin_port), ret));
		}
		DEBUG("%s: port number %d\n", __func__, ntohs(tmp_addr.sin_port));
	}


	return ret;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	return accept4(sockfd, addr, addrlen, 0);
}

#ifdef UDP_MODE
#ifndef CLIENT_MODE
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen){

	//hprintf("YO %d\n",  ntohs(((struct sockaddr_in*)addr)->sin_port));
	int ret = real_bind(sockfd, addr, addrlen);
	//hprintf("YO %d\n",  ntohs(((struct sockaddr_in*)addr)->sin_port));

#ifdef USE_PRE_PROCESS
	bool once = true;
	if(once){
		once = false;
		system("LD_PRELOAD= sh /tmp/run.sh");
	}
#endif
	/*
	struct sockaddr_in tmp_addr;
	int len = sizeof(struct sockaddr);
	if(ret != -1 && getsockname(sockfd, (struct sockaddr *) &tmp_addr, (void*)&len) != -1){
	*/
	//struct sockaddr_in tmp_addr = struct sockaddr_in
		if(ret != -1){

			bool exists = connection_exists(ntohs(((struct sockaddr_in*)addr)->sin_port));

			if(!exists){
				if(is_target_port(ntohs(((struct sockaddr_in*)addr)->sin_port))){
					DEBUG("%s: port number %d\n", __func__, ntohs(((struct sockaddr_in*)addr)->sin_port));

					add_connection(ntohs(((struct sockaddr_in*)addr)->sin_port));

					connect_to_server("127.0.0.1", ntohs(((struct sockaddr_in*)addr)->sin_port)); /* fix me */
					//hprintf("%s %d %d\n", __func__, tmp_addr.sin_port, ret);
					assert(set_server_socket_to_connection(ntohs(((struct sockaddr_in*)addr)->sin_port), sockfd));
				}
			}
		}
	//}


	return ret;
}
#endif
#endif


/*
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	hprintf("============ %s ===========", __func__);
	int ret = real_accept(sockfd, addr, addrlen);

	struct sockaddr_in tmp_addr;
	int len = sizeof(struct sockaddr);
	if(getsockname(sockfd, (struct sockaddr *) &tmp_addr, &len) != -1){
		
		hprintf("%s %d %d\n", __func__, tmp_addr.sin_port, ret);

		assert(set_server_socket_to_connection(ntohs(tmp_addr.sin_port), ret));
		DEBUG("%s: port number %d\n", __func__, ntohs(tmp_addr.sin_port));
	}

	return ret;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
	accept(sockfd, addr, addrlen);
}
*/

#ifndef UDP_MODE
#ifndef CLIENT_MODE

int listen(int sockfd, int backlog){
	struct sockaddr_in addr;
	int len = sizeof(struct sockaddr);

	//hprintf("=== %s\n", __func__);

	int ret = -1;

	if(getsockname(sockfd, (struct sockaddr *) &addr, (void*)&len) != -1){

		bool exists = connection_exists(ntohs(addr.sin_port));

		if(!exists){
			DEBUG("%s: port number %d\n", __func__, ntohs(addr.sin_port));
		}

		ret = real_listen(sockfd, backlog);
		
		if(!exists){
				if(is_target_port(ntohs(addr.sin_port))){ 
					add_connection(ntohs(addr.sin_port));
					connect_to_server("127.0.0.1", ntohs(addr.sin_port)); /* fix me */
					DEBUG("%s: DONE \n", __func__);

				}
		}
	}

	return ret; 
}
#endif
#endif

#ifdef CLIENT_MODE


void connect_to_client(int client_sockfd, const struct sockaddr *client_addr, socklen_t client_addrlen){
	socklen_t clilen;
	int server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in serv_addr, cli_addr;

	serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(get_harness_state()->nyx_net_port);

	/* Now bind the host address using bind() call.*/
  if (real_bind(server_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
    hprintf("ERROR on binding");
    exit(1);
  }

	real_listen(server_sockfd,1);



	int ret = real_connect(client_sockfd, client_addr, client_addrlen);


	clilen = sizeof(cli_addr);
  int newsockfd = real_accept(server_sockfd, (struct sockaddr *)&cli_addr, &clilen);

	hprintf("CONNECTED!\n");


}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){

	struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;

	bool exists = connection_exists(ntohs(addr_in->sin_port));

	if(!exists && ntohs(addr_in->sin_port) == get_harness_state()->nyx_net_port){

		//int ret = real_connect(sockfd, addr, addrlen);

		connect_to_client(sockfd, addr, addrlen);

		add_connection(ntohs(addr_in->sin_port));
		
		assert(set_server_socket_to_connection(ntohs(addr_in->sin_port), sockfd));

		hprintf("%s: -> PORT: %d SOCKfd: %d\n", __func__, ntohs(addr_in->sin_port), sockfd);
		return 0;
	}
	
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	
	return real_connect(sockfd, addr, addrlen);
}

#endif 

/* todo: add support for multiple fds */ 
uint64_t u64_tmp = 0;
int fd_tmp = 0;
int epfd_tmp = 0;
uint32_t events_tmps = 0;

/* fix this */
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event){
	if(server_socket_exists(fd)){
		assert(op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD || op == EPOLL_CTL_DEL);
		if(op == EPOLL_CTL_DEL){
			u64_tmp = 0;
			events_tmps = 0;
			fd_tmp = 0;
			epfd_tmp = 0;
		}
		else{
			u64_tmp = event->data.u64;
			events_tmps = event->events;
			fd_tmp = fd;
			epfd_tmp = epfd;
		}
		return 0;
	}
	return real_epoll_ctl(epfd, op, fd, event);
}


int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout){

		int ret = 0;

		if(u64_tmp && epfd == epfd_tmp){
			ret = real_epoll_wait(epfd, events, maxevents, 0);
			events[ret].data.u64 = u64_tmp;
			events[ret].events = events_tmps;
			ret++;
		}
		else{
			ret = real_epoll_wait(epfd, events, maxevents, 0);
		}
		return ret;
}


