/**
 * @file utils.h
 * @author xbudin05
 * @brief This file holds utilities for sender.
 */
#ifndef __UTILS__
#define __UTILS__

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../helpers/dnsHeader.h"
#include "../helpers/dnsUtils.h"

#define DEFAULT_IPV4 134744072  // IPv4 for google.com - 8.8.8.8
#define DEFAULT_IPV6 {8193, 18528, 18528, 0, 0, 0, 0, 25700}// IPv6 for google.com - 2001:4860:4860::6464
#define DEFAULT_NONE -1

typedef struct
{
    uint32_t ipv4;
    // __uint128_t ipv6[8] = DEFAULT_NONE;
    char host[STRING_SIZE + 1];     // +1 for '\0'
    char dst_file[STRING_SIZE + 1]; // +1 for '\0'
    FILE *src_file;
} data_cache;

int read_options(int argc, char **argv, data_cache *data);

int switchToTCP(int fd, const struct sockaddr *dest, unsigned char *packet, int length);

/**
 * @param proto Indicating used protocol, in case of TCP first 2 bytes are for size of packet
 */
void appendMessage(unsigned char *packet, int dns_length, const unsigned char *payload, int* length, int proto);

/**
 * @note Expecting proper ending with \0
 */
void appendFileName(unsigned char *packet, int dns_length, const unsigned char *);

#endif // !__UTILS__