/**
 * @file utils.c
 * @author xbudin05
 * @brief This file implements interface offered by utils.h
 */
#include "utils.h"
#include <stdio.h>
#include <arpa/inet.h>

int openUDP(struct sockaddr* server) {
    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        fprintf(stderr, "socket() failed");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
    { // maybe SO_REUSEPORT needed, not working now
        fprintf(stderr, "Unable to access port\n");
        return -1;
    }

    if (bind(fd, server, sizeof(struct sockaddr_in)) == -1)
    {
        fprintf(stderr, "bind() failed");
        close(fd);
        return -1;
    }
}