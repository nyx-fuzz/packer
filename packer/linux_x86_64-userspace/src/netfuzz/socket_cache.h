#pragma once

#include <stdint.h>
#include <stdbool.h>
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
//int server_socket_to_client_socket(int socket);
int set_select_fds(fd_set *set, fd_set *old_set);
void disable_connection_by_server_socket(int socket);
ssize_t real_send(int sockfd, const void *buf, size_t len, int flags);

int server_socket_to_port(int socket);