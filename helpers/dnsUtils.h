/**
 * @file dnsUtils.h
 * @author xbudin05
 * @brief This file contains interface for translating domains and IP addresses
 */
#ifndef __DNSUTILS__
#define __DNSUTILS__

#include <sys/types.h>

u_char *ReadName(unsigned char *reader, unsigned char *buffer, int *count);

void ChangetoDnsNameFormat(unsigned char *dns, unsigned char* host);

#endif // !__DNSUTILS__