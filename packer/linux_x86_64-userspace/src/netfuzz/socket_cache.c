#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <netinet/in.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <assert.h>
#include "socket_cache.h"
#include "nyx.h"
#include "syscalls.h"

#ifdef DEBUG_MODE
#define DEBUG(f_, ...) hprintf((f_), ##__VA_ARGS__)
#else
#define DEBUG(f_, ...) 
#endif

//FIXME: use harness_state() to get namespace name
#define NNS_NAME "nspce"

typedef struct interfaces_s {
	int server_sockets[8];
	uint8_t server_sockets_num;

	int client_sockets[8];
	uint8_t client_sockets_num;
	pthread_t client_thread; // TODO: add 8 thread support

	uint16_t port_server;
	uint16_t port_client;
	uint16_t port;
  bool disabled;

} interfaces_t;

typedef struct thread_args_s {
	struct sockaddr_in client;
	struct sockaddr_in server;
} thread_args_t;

#define MAX_CONNECTIONS 16

uint8_t active_connections = 0;
interfaces_t connections[MAX_CONNECTIONS] = {0};
uint8_t active_con_num = 0;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER; //TODO: add 8 mutexes?
pthread_cond_t server_ready = PTHREAD_COND_INITIALIZER;
pthread_cond_t client_ready = PTHREAD_COND_INITIALIZER;
bool server_ready_flag = false;
bool client_ready_flag = false;
char *client_thread_data_to_send;
size_t client_thread_data_to_send_len;

/* TODO: make this code thread safe */


static bool check_server_socket(interfaces_t* connection, int socket){
	DEBUG("%s: %d\n", __func__, socket);
/* check if already exists */
	for(uint8_t i = 0; i < connection->server_sockets_num; i++){
		if(connection->server_sockets[i] == socket){
			return true; /* server socket exists */
		}
	}
	return false; 
}

static bool check_client_socket(interfaces_t* connection, int socket){
	DEBUG("%s: %d\n", __func__, socket);
/* check if already exists */
	for(uint8_t i = 0; i < connection->client_sockets_num; i++){
		if(connection->client_sockets[i] == socket){
			return true; /* server socket exists */
		}
	}
	return false; 
}


static void add_server_socket(interfaces_t* connection, int socket){
	DEBUG("%s: %d\n", __func__, socket);

	if(!check_server_socket(connection, socket)){
		assert(connection->server_sockets_num < 8);
		connection->server_sockets[connection->server_sockets_num] = socket;
		connection->server_sockets_num++;
	}
}

static void add_client_socket(interfaces_t* connection, int socket){
	DEBUG("%s: %d\n", __func__, socket);

	if(!check_server_socket(connection, socket)){
		assert(connection->server_sockets_num < 8);
		connection->client_sockets[connection->client_sockets_num] = socket;
		connection->client_sockets_num++;
	}
}

static bool close_server_socket(interfaces_t* connection, int socket){
	DEBUG("%s: %d\n", __func__, socket);

	bool closed = false;

	if(check_server_socket(connection, socket)){

		for(uint8_t i = 0; i < connection->server_sockets_num; i++){

			if(closed){
				connection->server_sockets[i-1] = connection->server_sockets[i];
			}

			if(connection->server_sockets[i] == socket){
				//hprintf("%s -> %d\n", __func__, socket);
				closed = true;
			}
		
			//connection->client_sockets[connection->client_sockets_num] = socket;
		}
		if(closed){
			connection->server_sockets_num--;
			connection->client_sockets_num--;
		}

	}
	return closed;
}





/* ok */
bool connection_exists(uint16_t port){
	pthread_mutex_lock(&lock);
	DEBUG("%s: %d\n", __func__, port);

	for(uint8_t i = 0; i < active_connections; i++){
    if(connections[i].disabled == true){
      continue;
    }
		if(connections[i].port == port){
			pthread_mutex_unlock(&lock);
			return true;
		}
	} 

	pthread_mutex_unlock(&lock);
	return false;
}

/* modify -> multi FDs */
bool server_socket_exists(int socket){
	pthread_mutex_lock(&lock);
	DEBUG("%s: %d\n", __func__, socket);

	for(uint8_t i = 0; i < active_connections; i++){
    if(connections[i].disabled == true){
      continue;
    }

		if(check_server_socket(&connections[i], socket)){
			pthread_mutex_unlock(&lock);
			return true;
		}

	} 

	pthread_mutex_unlock(&lock);
	return false;
}

int server_socket_to_port(int socket){
	pthread_mutex_lock(&lock);
	DEBUG("%s: %d\n", __func__, socket);

	for(uint8_t i = 0; i < active_connections; i++){
    if(connections[i].disabled == true){
      continue;
    }

		if(check_server_socket(&connections[i], socket)){
			pthread_mutex_unlock(&lock);
			return connections[i].port;
		}
	} 

	pthread_mutex_unlock(&lock);
	return -1;
}


/* unused ? */
bool client_socket_exists(int socket){
	pthread_mutex_lock(&lock);
	DEBUG("%s: %d\n", __func__, socket);

	for(uint8_t i = 0; i < active_connections; i++){
    if(connections[i].disabled == true){
      continue;
    }

		if(check_client_socket(&connections[i], socket)){
			pthread_mutex_unlock(&lock);
			return true;
		}

	} 

	pthread_mutex_unlock(&lock);
	return false;
}

/* modify -> multi FDs */
bool set_server_socket_to_connection(uint16_t port, int socket){
	pthread_mutex_lock(&lock);
	DEBUG("%s: %d %d\n", __func__, socket, port);

	for(uint8_t i = 0; i < active_connections; i++){
    if(connections[i].disabled == true){
      continue;
    }
		if(connections[i].port == port){

			add_server_socket(&connections[i], socket);

			pthread_mutex_unlock(&lock);
			return true;
		}
	} 
	pthread_mutex_unlock(&lock);
	return false;
}

/* modify -> multi FDs or keep it? */
bool set_client_socket_to_connection(uint16_t port, int socket){
	pthread_mutex_lock(&lock);
	DEBUG("%s: %d %d\n", __func__, socket, port);

	for(uint8_t i = 0; i < active_connections; i++){
    if(connections[i].disabled == true){
      continue;
    }
		if(connections[i].port == port){
			add_client_socket(&connections[i], socket);

			pthread_mutex_unlock(&lock);
			return true;
		}
	} 
	pthread_mutex_unlock(&lock);
	return false;
}

static pthread_t get_thread_id_from_connection(uint16_t port){
	pthread_mutex_lock(&lock);
	pthread_t thread_id;

	for(uint8_t i = 0; i < active_connections; i++){
		if(connections[i].disabled == true){
			continue;
		}
		if(connections[i].port == port){
			thread_id = connections[i].client_thread;
			pthread_mutex_unlock(&lock);
			return thread_id;
		}
	}
	pthread_mutex_unlock(&lock);
	return -1;
}

static void move_thread_to_netns() {
	hprintf("%s: ", __func__);
	const char *netns_path_fmt = "/var/run/netns/%s";
	char netns_path[272]; /* 15 for "/var/.." + 256 for netns name + 1 '\0' */
	int netns_fd;

	if (strlen(NNS_NAME) > 256)
		hprintf("Network namespace name \"%s\" is too long\n", NNS_NAME);

	sprintf(netns_path, netns_path_fmt, NNS_NAME);

	netns_fd = open(netns_path, O_RDONLY);
	if (netns_fd == -1)
		hprintf("Unable to open %s\n", netns_path);

	if (setns(netns_fd, CLONE_NEWNET) == -1)
		hprintf("setns failed: %s\n", strerror(errno));
	hprintf("done\n");
}

char *hexdump_representation(const char *rcvbuf, size_t len) {
  if (rcvbuf == NULL) {
    return NULL;
  }

  size_t line_len = 76;               // Line length without any shift
  size_t hex_lines = (len + 15) / 16; // Calculate the number of lines needed
  size_t hex_len = hex_lines * line_len + 1; // Total length of hex_dump string
  char *hex_dump = (char *)malloc(hex_len * sizeof(char));

  if (hex_dump == NULL) {
    return NULL;
  }

  size_t hex_dump_pos = 0;
  for (size_t i = 0; i < len; i += 16) {
    int line_offset = snprintf(hex_dump + hex_dump_pos, 11, "%08zX  ", i);
    hex_dump_pos += line_offset;

    for (size_t j = 0; j < 16; j++) {
      if (i + j < len) {
        line_offset = snprintf(hex_dump + hex_dump_pos, 5, "%02X ",
                               (unsigned char)rcvbuf[i + j]);
      } else {
        line_offset = snprintf(hex_dump + hex_dump_pos, 5, "   ");
      }
      hex_dump_pos += line_offset;
      if (j == 7) {
        hex_dump[hex_dump_pos++] = ' ';
      }
    }

    hex_dump[hex_dump_pos++] = ' ';
    hex_dump[hex_dump_pos++] = '|';

    for (size_t j = 0; j < 16 && i + j < len; j++) {
      hex_dump[hex_dump_pos++] =
          (rcvbuf[i + j] >= 32 && rcvbuf[i + j] <= 126) ? rcvbuf[i + j] : '.';
    }

    hex_dump[hex_dump_pos++] = '|';
    hex_dump[hex_dump_pos++] = '\n';
  }
  hex_dump[hex_dump_pos] = '\0'; // Null-terminate the hex_dump string

  return hex_dump;
}

void wait_for_client()
{
	pthread_mutex_lock(&lock);

	while (!client_ready_flag)
		pthread_cond_wait(&client_ready, &lock);

	pthread_mutex_unlock(&lock);
}

void client_is_ready()
{
	pthread_mutex_lock(&lock);
	client_ready_flag = true;
	pthread_mutex_unlock(&lock);

	pthread_cond_signal(&client_ready);
}

void find_tcp_seq_numbers_of_connection(int raw_socket, uint32_t *seq_num_client, uint32_t *seq_num_server)
{
	char buffer[80]; //sizeof(struct iphdr) + max size of a tcp handshake packet (60)

	DEBUG("%s: Reading SYNACK to get seq numbers.\n", __func__);

	while (1) {
		ssize_t len = real_read(raw_socket, buffer, sizeof(buffer));
		if (len <= 0) {
			hprintf("%s: read error: %s\n", __func__, strerror(errno));
			exit(-1);
		}

		struct iphdr *iph = (struct iphdr *)buffer;
		struct tcphdr *tcph = (struct tcphdr *)((uint8_t *)iph + iph->ihl * 4);

		if (tcph->syn == 1 && tcph->ack == 1) {
			DEBUG("%s: found synack\n", __func__);
			*seq_num_server = ntohl(tcph->seq);
			*seq_num_client = ntohl(tcph->ack_seq) - 1;
			break;
		}
	}

	DEBUG("%s: Got SEQ client: %u, SEQ server: %u\n", __func__, *seq_num_client, *seq_num_server);
}

static void dump_payload(void* buffer, size_t len, const char* filename)
{
	static kafl_dump_file_t file_obj = {0};

	file_obj.file_name_str_ptr = (uintptr_t)filename;
	file_obj.append = 0;
	file_obj.bytes = 0;
	kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t) (&file_obj));

	file_obj.append = 1;
	file_obj.bytes = len;
	file_obj.data_ptr = (uintptr_t)buffer;
	kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t) (&file_obj));
}

static void send_tcp_numbers_to_main_fuzzer(uint32_t seq_num_client, uint32_t seq_num_server)
{
	uint32_t data[2] = {seq_num_client, seq_num_server};
	size_t size = sizeof(data);

	hprintf("%s: SEQ client: %u, SEQ server: %u\n", __func__, seq_num_client, seq_num_server);

	dump_payload(data, size, "tcp_sequence_numbers.bin");
}

void *client_thread_func(void *data)
{
	move_thread_to_netns();
	thread_args_t *args = (thread_args_t *)data;
	struct sockaddr_in server = args->server;
	struct sockaddr_in client = args->client;
	int handshake_socket;
	uint32_t seq_num_client = 0;
	uint32_t seq_num_server = 0;

	hprintf("%s: create socket...\n", __func__);

	handshake_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (handshake_socket == -1)
	{
		hprintf("socket error: %s\n", strerror(errno));
		exit(-1);
	}

	if (real_bind(handshake_socket, (struct sockaddr *)&client, sizeof(client)) < 0)
	{
		hprintf("bind error: %s\n", strerror(errno));
		exit(-1);
	}

	int send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (send_socket == -1) {
		hprintf("socket error: %s\n", strerror(errno));
		exit(-1);
	}

	if (real_bind(send_socket, (struct sockaddr *)&client, sizeof(client)) < 0) {
		hprintf("bind error: %s\n", strerror(errno));
		exit(-1);
	}

	//Connect to remote server
	hprintf("%s: connect to socket...\n", __func__);
	hprintf("%s: server port is %d\n", __func__, ntohs(server.sin_port));
	if (real_connect(handshake_socket, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		hprintf("connect error: %s\n", strerror(errno));
		exit(-1);
	}

	hprintf("%s: Connected. Handshake is done\n", __func__);

	find_tcp_seq_numbers_of_connection(send_socket, &seq_num_client, &seq_num_server);

	send_tcp_numbers_to_main_fuzzer(seq_num_client, seq_num_server);

	assert(set_client_socket_to_connection(ntohs(server.sin_port), handshake_socket));

	free(data);

	client_is_ready();

	while (1) {
		pthread_mutex_lock(&lock);

		while (!server_ready_flag)
			pthread_cond_wait(&server_ready, &lock);

		real_sendto(send_socket, client_thread_data_to_send,
					client_thread_data_to_send_len, 0,
					(struct sockaddr *)&server, sizeof(server));

#define DEBUG_MODE 1
#ifdef DEBUG_MODE
		{
			fflush(stdout);
			char *hexdumped_data = hexdump_representation(client_thread_data_to_send,
														  client_thread_data_to_send_len);
			hprintf("%s: Data that will be sended (%zu len):\n%s\n", __func__,
				  client_thread_data_to_send_len, hexdumped_data);
			free(hexdumped_data);
		}
#endif
#undef DEBUG_MODE

		server_ready_flag = false;
		pthread_mutex_unlock(&lock);
	}

	return NULL;
}

void send_malformed_data(char *data, size_t len)
{
	pthread_mutex_lock(&lock);
	client_thread_data_to_send = data;
	client_thread_data_to_send_len = len;
	server_ready_flag = true;
	pthread_mutex_unlock(&lock);

	pthread_cond_signal(&server_ready);
}

void create_client(struct sockaddr_in *server, struct sockaddr_in *client)
{
	DEBUG("%s: server ip: %s, server port: %d\n", __func__,
		inet_ntoa(server->sin_addr), ntohs(server->sin_port));
	DEBUG("%s: client ip: %s, client port: %d\n", __func__,
		inet_ntoa(client->sin_addr), ntohs(client->sin_port));

	thread_args_t *args = malloc(sizeof(thread_args_t));

	memcpy(&args->server, server, sizeof(struct sockaddr_in));
	memcpy(&args->client, client, sizeof(struct sockaddr_in));

	pthread_t thread_id =
		get_thread_id_from_connection(ntohs(server->sin_port));

	pthread_create(&thread_id, NULL, client_thread_func, args);
}

/* ok */
bool add_connection(uint16_t port){
	DEBUG("%s: %d\n", __func__, port);

	assert(!connection_exists(port));

	pthread_mutex_lock(&lock);

	if(active_con_num >= MAX_CONNECTIONS){
		/* TODO: replace with ABORT hypercall */
		hprintf("%s -> release\n", __func__);
		pthread_mutex_unlock(&lock);
		kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
	}
	//hprintf("%s -> port: %d\n", __func__, port);
	connections[active_connections].port = port;

	/* init fd cache */
	connections[active_connections].client_sockets_num = 0;
	connections[active_connections].server_sockets_num = 0;

	active_connections++;
	active_con_num++;
	pthread_mutex_unlock(&lock);
	return true;
}

/* modify -> multi FDs */
int set_select_fds(fd_set *set, fd_set *old_set){
	pthread_mutex_lock(&lock);
	//hprintf("%s -> %d\n", __func__, active_connections);
	int ret = 0;

	for(uint8_t i = 0; i < active_connections; i++){
    if(connections[i].disabled == true){
      continue;
    }

		for(uint8_t j = 0; j < connections[i].server_sockets_num; j++){
			if(FD_ISSET(connections[i].server_sockets[j], old_set)){
				FD_SET(connections[i].server_sockets[j], set);
				ret++;
			}
		}
	} 
		
	pthread_mutex_unlock(&lock);
	return ret;

}

/* modify -> multi FDs */
void disable_connection_by_server_socket(int socket){
	pthread_mutex_lock(&lock);
	DEBUG("%s: %d\n", __func__, socket);

  for(uint8_t i = 0; i < active_connections; i++){
    if(connections[i].disabled == true){
      continue;
    }

		if(close_server_socket(&connections[i], socket) && connections[i].server_sockets_num == 0){
			active_con_num--;
      connections[i].disabled = true;
            //TODO pthread_join here??
	  pthread_mutex_unlock(&lock);
			return;
		}

	}
  pthread_mutex_unlock(&lock);
}

uint16_t get_active_connections(void){
	DEBUG("%s\n", __func__);

  return active_con_num;
}
