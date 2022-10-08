/**
 * @file dns_receiver.c
 * @author xbudin05
 * @brief This file contains implementation of interface from dns_receiver.
 *  We receive dns queries as a form of communication with dns_sender
 */
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
#include "dns_receiver_events.h"

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif // !_XOPEN_SOURCE

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

int serverTCP(struct sockaddr_in *server, int encoding, unsigned char* path)
{
    struct sockaddr_in from;
    int newSock, msg_len;
    socklen_t len = sizeof(from);
    unsigned char buffer_b[TCP_MTU];
    int fileSize = 0;
    int chunk = 0;

    while (true)
    {
        chunk++;
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
            unsigned char *buffer = buffer_b;
            // reading message
            if ((msg_len = read(newSock, buffer, TCP_MTU)) < 0)
            {
                fprintf(stderr, "Unable to read from TCP stream\n");
                return false;
            }

            dns_receiver__on_chunk_received(&from.sin_addr, path, chunk, msg_len);

            // skip TCP_OFFSET data
            if (total == 0)
            {
                msg_len -= TCP_OFFSET;
                buffer += TCP_OFFSET;
            }

            int received = msg_len;

            // last packet received
            if (checkProto((dns_header *)buffer, OPEN_UDP))
                last = true;

            unsigned char *payload = readPayload(buffer, &received, total == 0);

            ptrdiff_t diff = payload - buffer;
            msg_len = msg_len - diff; // actual size of the payload

            // first packet
            if (total == 0)
            {
                current = 0;
                total = received;

                // skip file name, which is in the beggining
                msg_len -= (strlen(payload) + 1);
                payload = payload + strlen(payload) + 1;
            }
            current += msg_len;

            dns_receiver__on_query_parsed(path, payload);

            if (encoding)
                decode(payload, msg_len);

            fileSize += msg_len;
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
            return fileSize;
        }
    }

    return fileSize;
}

int serverUDP(struct sockaddr_in *server, char **argv, int argStart, int encoding)
{
    unsigned char host[STRING_SIZE + 1];
    ChangetoDnsNameFormat(host, argv[argStart]);
    unsigned char *path = argv[argStart + 1];

    int msg_size, i;
    unsigned char buffer[UDP_MTU];
    struct sockaddr_in client;
    socklen_t length;

    length = sizeof(client);
    fprintf(stderr, "Starting UDP server\n");

    while ((msg_size = recvfrom(udp, buffer, UDP_MTU, 0, (struct sockaddr *)&client, &length)) >= 0)
    {
        int fileSize = 0;
        fprintf(stderr, "Server received packet\n");
        dns_receiver__on_transfer_init(&client.sin_addr);
        dns_receiver__on_chunk_received(&client.sin_addr, path, 0, msg_size);

        unsigned char reply[UDP_MTU];

        unsigned char returnCode[RETURN_CODE] = "received request";
        unsigned char *payload = readPayload(buffer, &msg_size, true);
        int headerLength = payload - buffer;

        dns_receiver__on_query_parsed(path, payload);

        memcpy(reply, buffer, headerLength);
        ((dns_header *)reply)->q_count = htons(1);

        unsigned char *qname = &buffer[HEADER_SIZE]; // skip header and point to first qname

        if (strcmp(qname, host) != 0)
        {
            fprintf(stderr, "Host name does not match\n");
            strcpy(returnCode, "Host name does not match");
            sendReply(udp, reply, headerLength, (struct sockaddr *)&client, returnCode, encoding);
            continue;
        }

        sendReply(udp, reply, headerLength, (struct sockaddr *)&client, returnCode, encoding);

        // unable to open file, just send a reply
        int fileLength;
        if (!openFile(path, &payload, &fileLength))
        {
            strcpy(returnCode, "unable to open file");
            sendReply(udp, reply, headerLength, (struct sockaddr *)&client, returnCode, encoding);
            continue;
        }

        // checks if TCP is needed, otherwise writes data here
        if (checkProto((dns_header *)buffer, OPEN_TCP))
        { // TCP needed
            fprintf(stderr, "TCP connection needed\n");
            if ((fileSize = serverTCP(server, encoding, path)) == 0)
                strcpy(returnCode, "TCP transfer failed");
        }
        else
        { // all payload in current UDP packet
            fprintf(stderr, "UDP connection sufficient\n");

            if (encoding)
                decode(payload, msg_size);

            fileSize = msg_size;
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
        strcpy(returnCode, "All good");
        sendReply(udp, reply, headerLength, (struct sockaddr *)&client, returnCode, encoding);

        fprintf(stderr, "Transfer finished, waiting for new client\n");
        dns_receiver__on_transfer_completed(path, fileSize);
    }

    return true;
}

int main(int argc, char **argv)
{
    int c, encoding = true;
    opterr = 0;
    while ((c = getopt(argc, argv, "d")) != -1)
    {

        switch (c)
        {
        case 'd':
            encoding = false;
            break;
        }
    }

    if (optind < 1 || optind >= argc)
    {
        fprintf(stderr, "Missing arguments\n");
        return -1;
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT);

    signal(SIGINT, my_handler);

    if (!openUDP((struct sockaddr *)&server) || !openTCP((struct sockaddr *)&server))
        return -1;

    serverUDP(&server, argv, optind, encoding);

    // dead code
    fclose(output);
    close(udp);
    close(tcp);

    return -1;
}