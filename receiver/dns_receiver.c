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

void my_handler(int s) {

    if (output != NULL)
        fclose(output);

    close(fd);
    exit(0);
}

int serverTCP(struct sockaddr_in *server) {
    // TODO
}

/**
 * @return -1 upon problem
 * @return 1 upon need for TCP server
 * @return 0 should not happen
 */
int serverUDP(struct sockaddr_in *server, char** argv) {

    unsigned char* path = argv[2];

    int msg_size, i;
    char buffer[MTU], qname[STRING_SIZE + 1], file[STRING_SIZE + 1];
    struct sockaddr_in client;
    socklen_t length;

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        err(1, "socket() failed");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1) { // maybe SO_REUSEPORT needed, not working now
        fprintf(stderr, "Unable to access port\n");
        return -1;
    }

    if (bind(fd, (struct sockaddr *)server, sizeof(struct sockaddr_in)) == -1) {
        err(1, "bind() failed");
        close(fd);
        return -1;
    }
    length = sizeof(client);

    while ((msg_size = recvfrom(fd, buffer, MTU, 0, (struct sockaddr *)&client, &length)) >= 0) {

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
        unsigned char* fullPath = (unsigned char*)malloc(strlen(path) + strlen(file) + 1);
        memset(fullPath, '\0', strlen(path) + strlen(file) + 1);
        strcpy(fullPath, path);
        strcpy(&fullPath[strlen(path)], file);

        if ((output = fopen(fullPath, "wb")) == NULL) {
            fprintf(stderr, "Unable to open file [%s]\n", fullPath);
            return -1;
        }

        // checks if TCP is needed, otherwise writes data here
        if (((dns_header*)&buffer)->q_count == htons(2)) { // TCP needed
            // TODO
            serverTCP(server);
        } else {    // all payload in current UDP packet
            for (int i = 0; i < msg_size; i++) {
                if (fputc(*payload, output) == EOF) {
                    fprintf(stderr, "Problem writing into file\n");
                    return -1;
                }
                payload++;
            }
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    
    if (argc < 3) {
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