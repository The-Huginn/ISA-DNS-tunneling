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
#include <string.h>
#include <stdlib.h>

int openUDP(struct sockaddr *server)
{
    if ((udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        fprintf(stderr, "socket() failed");
        return false;
    }

    if (setsockopt(udp, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
    { // maybe SO_REUSEPORT needed, not working now
        fprintf(stderr, "Unable to access port\n");
        return false;
    }

    if (bind(udp, server, sizeof(struct sockaddr_in)) == -1)
    {
        fprintf(stderr, "bind() failed");
        close(udp);
        return false;
    }

    return true;
}

int openTCP(struct sockaddr *server)
{
    if ((tcp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
        fprintf(stderr, "socket(): could not create the socket\n");
        return false;
    }

    if (bind(tcp, (struct sockaddr *)server, sizeof(struct sockaddr_in)) < 0)
    {
        fprintf(stderr, "TCP binding failed'n");
        return false;
    }

    if (setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
    {
        fprintf(stderr, "Unable to access port\n");
        return false;
    }

    if (listen(tcp, 1) == -1)
    {
        fprintf(stderr, "TCP listen failed\n");
        return false;
    }

    return true;
}

int openFile(unsigned char *path, unsigned char **buffer, int *fileLength)
{
    unsigned char file[STRING_SIZE + 1] = {'\0'};
    // read file name
    strcpy(file, *buffer);
    *buffer = *buffer + strlen(file) + 1;
    *fileLength = strlen(file) + 1;
    
    // open file
    unsigned char *fullPath = (unsigned char *)malloc(strlen(path) + strlen(file) + 1);
    memset(fullPath, '\0', strlen(path) + strlen(file) + 1);
    strcpy(fullPath, path);
    strcpy(&fullPath[strlen(path)], file);

    if ((output = fopen(fullPath, "w")) == NULL)
    {
        fprintf(stderr, "Unable to open file [%s]\n", fullPath);
        return false;
    }

    return true;
}
