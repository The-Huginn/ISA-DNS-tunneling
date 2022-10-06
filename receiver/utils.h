/**
 * @file utils.h
 * @author xbudin05
 * @brief This file contains utilities for dns receiver
 */
#ifndef __UTILS__
#define __UTILS__
#include <arpa/inet.h>
#include <stdio.h>

extern int udp;
extern int tcp;
extern FILE* output;

int openUDP(struct sockaddr* server);

int openTCP(struct sockaddr* server);

/**
 * @param buffer 
 * @param msg_size 
 * @param payload 
 * @return actual start of payload
 */
unsigned char * readPayload(unsigned char* buffer, int* msg_size, int first);

int openFile(unsigned char* path, unsigned char* buffer);

#endif // !__UTILS__