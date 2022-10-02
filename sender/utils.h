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

#define true 1
#define false 0
#define STRING_SIZE 255
#define MTU 1400        // some room for lower layers
#define HEADER_SIZE sizeof(dns_header)
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

void initHeader(dns_header *dns);

int switchToTCP(int fd, const struct sockaddr *dest, unsigned char *packet, int length);

void appendMessage(unsigned char *packet, int dns_length, const unsigned char *payload, int length);

#endif // !__UTILS__