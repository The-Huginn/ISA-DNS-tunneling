/**
 * @file dns_sender.cpp
 * @author xbudin05
 * @brief This file implements dns_sender interface for communicating with dns server via tunneling
 */

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include <regex.h>

#define IP_ADDR "127.0.0.1" // a fixed server IP address
#define PORT 3009           // a fixed server port
#define BUFFER 1024         // buffer length

#define true 1
#define false 0
#define STRING_SIZE 255

typedef struct
{
    uint32_t ipv4 = 0;
    uint16_t ipv6 = 0;
    char host[STRING_SIZE + 1] = {'\0'};     // +1 for '\0'
    char dst_file[STRING_SIZE + 1] = {'\0'}; // +1 for '\0'
    FILE *src_file = stdin;
} data_cache;

int read_options(int argc, char **argv, data_cache *data)
{

    int c;
    // Suppresses warnings in stderr
    opterr = 0;
    while ((c = getopt(argc, argv, "b:u:")) != -1)
    {

        switch (c)
        {
        case 'b': // base host
            memcpy(data->host, optarg, STRING_SIZE);
            break;

        case 'u': // upstream dns ip
            data->ipv4 = inet_addr(optarg);
            if (data->ipv4 == -1) {
                fprintf(stderr, "Invalid IPv4 address\n");
                return false;
            }
            break;

        case '?':
        case ':':
            fprintf(stderr, "Unknown option or missing argument...\n");
            return false;
            break;

        default:
            fprintf(stderr, "Problemo\n");
            return false;
            break;
        }
    }

    if (optind < 1 || optind >= argc)
    {
        fprintf(stderr, "Missing destination file\n");
        return false;
    }

    memcpy(data->dst_file, argv[optind], STRING_SIZE);
    optind++;

    // We take input from stdin
    if (optind >= argc)
        return true;

    data->src_file = fopen(argv[optind], "r");

    if (data->src_file == NULL)
    {
        fprintf(stderr, "Unable to open provided input file\n");
        return false;
    }

    return true;
}

int main(int argc, char *argv[])
{
    data_cache data;
    if (read_options(argc, argv, &data) == false)
        return -1;

    int sock, msg_size, i;
    struct sockaddr_in server, from;
    socklen_t len;
    char buffer[BUFFER];

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) // create a client socket
        err(1, "socket() failed\n");

    printf("* Socket created\n");

    server.sin_addr.s_addr = inet_addr(IP_ADDR); // set the server address
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT); // set the server port (network byte order)

    len = sizeof(server);

    // read data from a user and send them to the server
    while ((msg_size = read(STDIN_FILENO, buffer, BUFFER)) > 0)
    // read input data from STDIN (console) until end-of-line (Enter) is pressed
    // when end-of-file (CTRL-D) is received, n == 0
    {
        i = sendto(sock, buffer, msg_size, 0, (struct sockaddr *)&server, len); // send data to the server
        if (i == -1)                                                            // check if data was sent correctly
            err(1, "sendto() failed");
        else if (i != msg_size)
            err(1, "sendto(): buffer written partially");
        len = sizeof(from);

        // obtain the local port number assigned by the OS
        if (getsockname(sock, (struct sockaddr *)&from, &len) == -1)
            err(1, "getsockname() failed");

        printf("* Data sent from port %d (%d) to %s, port %d (%d)\n", ntohs(from.sin_port), from.sin_port, inet_ntoa(server.sin_addr), ntohs(server.sin_port), server.sin_port);

        // read the answer from the server
        if ((i = recvfrom(sock, buffer, BUFFER, 0, (struct sockaddr *)&from, &len)) == -1)
            err(1, "recvfrom() failed");
        else if (i > 0)
        {
            printf("* UDP packet received from %s, port %d (%d)\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port), from.sin_port);
            printf("%.*s", i, buffer); // print the answer
        }
    }
    // read data until end-of-file (CTRL-D)

    if (msg_size == -1)
        err(1, "reading failed");
    close(sock);
    printf("* Closing the client socket ...\n");
    return 0;
}