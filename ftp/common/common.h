#ifndef COMMON_H
#define COMMON_H

#include "../../crypto_utils/include/ecdh/ecdh.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h> // getaddrinfo()
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* constants */
#define DEBUG 1
#define MAXSIZE 512 // max buffer size
#define CLIENT_PORT_ID 30020

/* Holds command code and argument */
struct command {
  char arg[255];
  char code[5];
};

/**
 * Create listening socket on remote host
 * Returns -1 on error, socket fd on success
 */
int socket_create(int port);

/**
 * Create new socket for incoming client connection request
 * Returns -1 on error, or fd of newly created socket
 */
int socket_accept(int sock_listen);

/**
 * Connect to remote host at given port
 * Returns socket fd on success, -1 on error
 */
int socket_connect(int port, char *host);

/**
 * Receive data on sockfd
 * Returns -1 on error, number of bytes received
 * on success
 */
int recv_data(int sockfd, char *buf, int bufsize);

/**
 * Send resposne code on sockfd
 * Returns -1 on error, 0 on success
 */
int send_response(int sockfd, int rc);

//------------------- UTILITY FUNCTIONS-------------------//

/**
 * Trim whiteshpace and line ending
 * characters from a string
 */
void trimstr(char *str, int n);

/**
 * Read input from command line
 */
void read_input(char *buffer, int size);

void split_mpz_t(mpz_t shared, unsigned char *high, unsigned char *low);

void print_bytes(const unsigned char *data, size_t size);

int read_hex_file_to_bytes(const char *filename, uint8_t *buffer, size_t size);
#endif
