/**
 * @file dnsUtils.h
 * @author xbudin05
 * @brief This file contains interface for translating domains and IP addresses
 */
#ifndef __DNSUTILS__
#define __DNSUTILS__

#include <sys/types.h>

#include "dnsHeader.h"

#define true 1
#define false 0
#define STRING_SIZE 255
#define MTU 1400        // some room for lower layers
#define HEADER_SIZE sizeof(dns_header)

u_char *ReadName(unsigned char *reader, unsigned char *buffer, int *count);

void ChangetoDnsNameFormat(unsigned char *dns, unsigned char* host);

#endif // !__DNSUTILS__