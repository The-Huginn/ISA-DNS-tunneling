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

    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        fprintf(stderr, "socket(): could not create the socket");
        return false;
    }

    if( bind(fd,(struct sockaddr *)&server , sizeof(server)) < 0) {
        fprintf(stderr,"bind() failed");
        return false;
    }

    if (listen(fd, 1) == -1) {
        fprintf(stderr, "listen() failed");
        return false;
    }

    struct sockaddr_in from;
    int len = sizeof(from), newSock, msg_len;
    char buffer[MTU];

    while (true) {
        if ((newSock = accept(newSock, (struct sockaddr*)&from, (socklen_t*)&len)) == -1) {
            fprintf(stderr, "accept failed\n");
            return false;
        }

        // reading message
        if ((msg_len = read(newSock, buffer, MTU)) < 0) {
            fprintf(stderr, "Unable to read from TCP stream\n");
            return false;
        }
        // write buffer to file

        // last packet received
        if (checkProto((dns_header*)buffer, OPEN_UDP)) {
            close(fd);
            openUDP((struct sockaddr*)server);
            break;
        }
    }

    return true;
}

/**
 * @return -1 upon problem
 * @return 1 upon need for TCP server
 * @return 0 should not happen
 */
int serverUDP(struct sockaddr_in *server, char **argv)
{

    unsigned char *path = argv[2];

    int msg_size, i;
    char buffer[MTU], qname[STRING_SIZE + 1], file[STRING_SIZE + 1];
    struct sockaddr_in client;
    socklen_t length;

    openUDP((struct sockaddr*)server);

    length = sizeof(client);

    while ((msg_size = recvfrom(fd, buffer, MTU, 0, (struct sockaddr *)&client, &length)) >= 0)
    {

        // copy qname
        strcpy(qname, &buffer[HEADER_SIZE]);

        // skip header and qname
        unsigned char *payload = &buffer[HEADER_SIZE + strlen(qname) + 1 + sizeof(question)];

        // read file name
        strcpy(file, payload);
        payload = &payload[strlen(file) + 1];
        // Shoudl work, rather check TODO
        msg_size -= (int)buffer - (int)payload;
        // msg_size -= HEADER_SIZE + strlen(qname) + 1 + sizeof(question) + strlen(file) + 1;

        // open file
        unsigned char *fullPath = (unsigned char *)malloc(strlen(path) + strlen(file) + 1);
        memset(fullPath, '\0', strlen(path) + strlen(file) + 1);
        strcpy(fullPath, path);
        strcpy(&fullPath[strlen(path)], file);

        if ((output = fopen(fullPath, "wb")) == NULL)
        {
            fprintf(stderr, "Unable to open file [%s]\n", fullPath);
            return -1;
        }

        // checks if TCP is needed, otherwise writes data here
        if (((dns_header *)&buffer)->q_count == htons(2))
        { // TCP needed
            // TODO
            if (!serverTCP(server)) {
                return false;
            }
        }
        else
        { // all payload in current UDP packet
            for (int i = 0; i < msg_size; i++)
            {
                if (fputc(*payload, output) == EOF)
                {
                    fprintf(stderr, "Problem writing into file\n");
                    return -1;
                }
                payload++;
            }
        }

        // send reply
    }

    return 0;
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

    close(fd);

    return 0;
}