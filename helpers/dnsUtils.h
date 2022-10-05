/**
 * @file dnsUtils.h
 * @author xbudin05
 * @brief This file contains interface for translating domains and IP addresses
 */
#ifndef __DNSUTILS__
#define __DNSUTILS__

#include <sys/types.h>
#include <arpa/inet.h>

#include "dnsHeader.h"

#define true 1
#define false 0
#define STRING_SIZE 255
#define TCP_MTU 1400        // some room for lower layers
#define UDP_MTU 512         // By RFC 1035
#define HEADER_SIZE sizeof(dns_header)
#define OPEN_UDP 1
#define OPEN_TCP 2
#define RETURN_CODE 50

u_char *ReadName(unsigned char *reader, unsigned char *buffer, int *count);

void ChangetoDnsNameFormat(unsigned char *dns, unsigned char* host);

void initHeader(dns_header *dns);

int sendReply(int fd, unsigned char* returnCode, unsigned char* qname, struct sockaddr* client);

/**
 * @return true upon proto being the same as q_count
 */
int checkProto(dns_header* dns, int proto);

#endif // !__DNSUTILS__