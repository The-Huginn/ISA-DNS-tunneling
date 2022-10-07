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

unsigned char *readPayload(unsigned char *buffer, int *msg_size, int first, int proto)
{
    if (first == false)
        return buffer;

    unsigned char qname[STRING_SIZE + 1] = {'\0'};
    // copy qname
    strcpy(qname, &buffer[HEADER_SIZE]);
    int length = HEADER_SIZE;
    length += strlen(qname) + 1;

    length += sizeof(question);
    unsigned char *payload = &buffer[length];

    payload = &payload[strlen(&buffer[length]) + 1];    // skip file name
    length += strlen(&buffer[length]) + 1;
    *msg_size -= length;
    if (proto == OPEN_TCP)    // we do not consider +2 for payload
        *msg_size -= 2;

    decode(&buffer[length], *msg_size);
    return &buffer[length];
}

int openFile(unsigned char *path, unsigned char *buffer)
{
    unsigned char qname[STRING_SIZE + 1] = {'\0'}, file[STRING_SIZE + 1] = {'\0'};
    // copy qname
    strcpy(qname, &buffer[HEADER_SIZE]);

    unsigned char *payload = &buffer[HEADER_SIZE + strlen(qname) + 1 + sizeof(question)];

    // read file name
    strcpy(file, payload);
    
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
