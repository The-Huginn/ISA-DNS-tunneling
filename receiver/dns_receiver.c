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
#include <stddef.h>

#include "utils.h"
#include "../helpers/dnsUtils.h"

int udp;
int tcp;
FILE *output = NULL;

void my_handler(int s)
{

    if (output != NULL)
        fclose(output);

    close(udp);
    close(tcp);
    exit(0);
}

int serverTCP(struct sockaddr_in *server)
{
    struct sockaddr_in from;
    int newSock, msg_len;
    socklen_t len = sizeof(from);
    unsigned char buffer[TCP_MTU];

    while (true)
    {
        if ((newSock = accept(tcp, (struct sockaddr *)&from, &len)) == -1)
        {
            fprintf(stderr, "accept failed\n");
            return false;
        }

        int total = 0;
        int current = 1; // cant be same as total
        int last = false;

        while (total != current)
        {

            // reading message
            if ((msg_len = read(newSock, buffer, TCP_MTU)) < 0)
            {
                fprintf(stderr, "Unable to read from TCP stream\n");
                return false;
            }

            int received = msg_len;

            // last packet received
            if (checkProto((dns_header *)buffer, OPEN_UDP))
                last = true;

            unsigned char *payload = readPayload(buffer, &received, total == 0);

            ptrdiff_t diff = buffer - payload;
            msg_len = diff; // actual size of the payload

            // first packet
            if (total == 0)
            {
                current = 0;
                total = received;
            }
            current += msg_len;

            decode(payload, msg_len);
            for (int i = 0; i < msg_len; i++)
            {
                if (fputc(payload[i], output) == EOF)
                {
                    fprintf(stderr, "Problem writing into file\n");
                    return false;
                }
            }
            fprintf(stderr, "%d:%d\n", total, current);
            msg_len = payload[msg_len - 1];
        }

        close(newSock);

        if (last)
        {
            fprintf(stderr, "Last packet received, listening on UDP again\n");
            return true;
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

    length = sizeof(client);
    fprintf(stderr, "Starting UDP server\n");

    while ((msg_size = recvfrom(udp, buffer, UDP_MTU, 0, (struct sockaddr *)&client, &length)) >= 0)
    {
        fprintf(stderr, "Server received packet\n");

        unsigned char reply[UDP_MTU];
        int headerLength = msg_size;

        unsigned char returnCode[RETURN_CODE] = "received request\0";
        unsigned char *payload = readPayload(buffer, &msg_size, true);
        headerLength -= msg_size;

        memcpy(reply, buffer, headerLength);
        unsigned char *qname = &buffer[HEADER_SIZE]; // skip header and point to first qname

        sendReply(udp, reply, headerLength, (struct sockaddr *)&client, returnCode);

        // unable to open file, just send a reply
        if (!openFile(path, buffer))
        {
            strcpy(returnCode, "unable to open file");
            sendReply(udp, reply, headerLength, (struct sockaddr *)&client, returnCode);
            continue;
        }

        // checks if TCP is needed, otherwise writes data here
        if (checkProto((dns_header *)buffer, OPEN_TCP))
        { // TCP needed
            fprintf(stderr, "TCP connection needed\n");
            if (!serverTCP(server))
                strcpy(returnCode, "TCP transfer failed");
        }
        else
        { // all payload in current UDP packet
            fprintf(stderr, "UDP connection sufficient\n");
            decode(payload, msg_size);
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
        output = NULL;
        // send a reply
        strcpy(returnCode, "OK");
        sendReply(udp, reply, headerLength, (struct sockaddr *)&client, returnCode);

        fprintf(stderr, "Transfer finished, waiting for new client\n");
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
    server.sin_port = htons(5556);

    signal(SIGINT, my_handler);

    if (!openUDP((struct sockaddr *)&server) || !openTCP((struct sockaddr *)&server))
        return -1;

    serverUDP(&server, argv);

    // dead code
    fclose(output);
    close(udp);
    close(tcp);

    return -1;
}