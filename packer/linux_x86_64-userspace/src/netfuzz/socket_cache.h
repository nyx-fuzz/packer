#pragma once

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

uint16_t get_active_connections(void);
bool connection_exists(uint16_t port);
bool server_socket_exists(int socket);
bool client_socket_exists(int socket);
bool set_server_socket_to_connection(uint16_t port, int socket);
bool set_client_socket_to_connection(uint16_t port, int socket);
bool add_connection(uint16_t port);
int set_select_fds(fd_set *set, fd_set *old_set);
void disable_connection_by_server_socket(int socket);
ssize_t real_send(int sockfd, const void *buf, size_t len, int flags);
void send_malformed_data(char *data, size_t len);
void wait_for_client();
void create_client(struct sockaddr_in *server, struct sockaddr_in *client);

int server_socket_to_port(int socket);
