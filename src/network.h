#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include "util.h"

// Socket families
#define UNIX    0
#define INET    0

/* Set non-blocking socket */
int set_nonblocking(int);

/*
 * Set TCP_NODELAY flat go true, disabling Nagle's algorithm,
 * no more waiting for incoming packets on the buffer
 */
int set_tcp_nodelay(int);

/* Auxiliary function for creating epoll server */
int create_and_bind(const char *, const char *, int);

/* Create non-blocking socket and make it listen on specified address
 * and port*/
int make_listen(const char *, const char *, int);

/* Accept a connection and add it to the right epollfd */
int accept_connection(int);

/* I/O management functions */

/*
 * Send all data in a loop, avoiding interruption based
 * on the kernel buffer availability
 */
ssize_t recv_bytes(int, unsigned char *, size_t);

/*
 * Receive (read) an arbitrary number of bytes from a file descriptor
 * and store them in a buffer
 */
ssize_t recv_bytes(int, unsigned char *, size_t);

#endif
