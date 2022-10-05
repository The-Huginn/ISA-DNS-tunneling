/**
 * @file dns_receiver.c
 * @author xbudin05
 * @brief This file contains implementation of interface from dns_receiver.
 *  We receive dns queries as a form of communication with dns_sender
 */
#include "dns_receiver.h"

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "utils.h"
#include "../helpers/dnsUtils.h"

int fd;
FILE *output = NULL;

void my_handler(int s)
{

    if (output != NULL)
        fclose(output);

    close(fd);
    exit(0);
}

int serverTCP(struct sockaddr_in *server)
{
    close(fd);

    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
    {
        fprintf(stderr, "socket(): could not create the socket\n");
        return false;
    }

    if (bind(fd, (struct sockaddr *)server, sizeof(struct sockaddr_in)) < 0)
    {
        err(1, "help");
        fprintf(stderr, "TCP binding failed'n");
        return false;
    }

    if (listen(fd, 1) == -1)
    {
        fprintf(stderr, "TCP listen failed\n");
        return false;
    }

    struct sockaddr_in from;
    int newSock, msg_len;
    socklen_t len = sizeof(from);
    char buffer[TCP_MTU];

    while (true)
    {
        if ((newSock = accept(fd, (struct sockaddr *)&from, &len)) == -1)
        {
            err(1, "help");
            fprintf(stderr, "accept failed\n");
            return false;
        }

        // reading message
        if ((msg_len = read(newSock, buffer, TCP_MTU)) < 0)
        {
            fprintf(stderr, "Unable to read from TCP stream\n");
            return false;
        }

        for (int i = 0; i < msg_len; i++)
        {
            if (fputc(buffer[i], output) == EOF)
            {
                fprintf(stderr, "Problem writing into file\n");
                return false;
            }
        }

        // last packet received
        if (checkProto((dns_header *)buffer, OPEN_UDP))
        {
            close(fd);
            return openUDP((struct sockaddr *)server);
        }
    }

    return true;
}

int serverUDP(struct sockaddr_in *server, char **argv)
{

    unsigned char *path = argv[2];

    int msg_size, i;
    char buffer[UDP_MTU];
    struct sockaddr_in client;
    socklen_t length;

    if (!openUDP((struct sockaddr *)server))
        return false;

    length = sizeof(client);

    while ((msg_size = recvfrom(fd, buffer, UDP_MTU, 0, (struct sockaddr *)&client, &length)) >= 0)
    {
        unsigned char qname[STRING_SIZE + 1] = {'\0'}, file[STRING_SIZE + 1] = {'\0'};
        fprintf(stderr, "Server received packet\n");
        unsigned char returnCode[RETURN_CODE] = "OK\0";

        // copy qname
        strcpy(qname, &buffer[HEADER_SIZE]);

        // skip header and qname
        unsigned char *payload = &buffer[HEADER_SIZE + strlen(qname) + 1 + sizeof(question)];

        // read file name
        strcpy(file, payload);
        payload = &payload[strlen(file) + 1];
        // Should work, rather check TODO
        msg_size -= (unsigned char*)buffer - (unsigned char*)payload;
        // msg_size -= HEADER_SIZE + strlen(qname) + 1 + sizeof(question) + strlen(file) + 1;

        // open file
        unsigned char *fullPath = (unsigned char *)malloc(strlen(path) + strlen(file) + 1);
        memset(fullPath, '\0', strlen(path) + strlen(file) + 1);
        strcpy(fullPath, path);
        strcpy(&fullPath[strlen(path)], file);

        if ((output = fopen(fullPath, "w")) == NULL)
        {
            fprintf(stderr, "Unable to open file [%s]\n", fullPath);
            strcpy(returnCode, "unable to open file");
        }

        // checks if TCP is needed, otherwise writes data here
        if (checkProto((dns_header*)buffer, OPEN_TCP))
        { // TCP needed
            fprintf(stderr, "TCP connection needed\n");
            if (!serverTCP(server))
                strcpy(returnCode, "TCP transfer failed");
        }
        else
        { // all payload in current UDP packet
            fprintf(stderr, "UDP connection sufficient\n");
            for (int i = 0; i < msg_size; i++)
            {
                if (fputc(payload[i], output) == EOF)
                {
                    fprintf(stderr, "Problem writing into file\n");
                    strcpy(returnCode, "unable to write to file");
                }
            }
        }

        fclose(output);
        // send a reply
        sendReply(fd, returnCode, qname, (struct sockaddr*)&client);
    }

    return true;
}

int main(int argc, char **argv)
{

    if (argc < 3)
    {
        fprintf(stderr, "Missing arguments\n");
        return -1;
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    signal(SIGINT, my_handler);

    serverUDP(&server, argv);

    // dead code
    fclose(output);
    close(fd);

    return -1;
}