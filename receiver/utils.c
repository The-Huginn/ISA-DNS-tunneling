/**
 * @file utils.c
 * @author xbudin05
 * @brief This file implements interface offered by utils.h
 */
#include "../helpers/dnsUtils.h"
#include "utils.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>


int openUDP(struct sockaddr* server) {
    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        fprintf(stderr, "socket() failed");
        return false;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
    { // maybe SO_REUSEPORT needed, not working now
        fprintf(stderr, "Unable to access port\n");
        return false;
    }

    if (bind(fd, server, sizeof(struct sockaddr_in)) == -1)
    {
        fprintf(stderr, "bind() failed");
        close(fd);
        return false;
    }

    return true;
}