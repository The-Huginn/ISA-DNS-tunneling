/**
 * @file utils.c
 * @author xbudin05
 * @brief This file implements interface offered in utils.h
 */

#include "utils.h"

#ifndef _XOPEN_SOURCE
    #define _XOPEN_SOURCE
#endif // !_XOPEN_SOURCE

 int read_options(int argc, char **argv, data_cache *data) {
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
            if (data->ipv4 == -1)
            {
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

    if (data->host[0] == '\0') {
        fprintf(stderr, "Missing host\n");
        return false;
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

int switchToTCP(int fd, const struct sockaddr *dest, unsigned char *packet, int length) {
    close(fd);
    
    // open TCP
    if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        perror("socket() failed\n");
        return false;
    }

    if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
        perror("connect() failed\n");
        return false;
    }

    return true;
}

void appendMessage(unsigned char *packet, int dns_length, const unsigned char *payload, int* length, int proto) {

    packet = &packet[dns_length];
    if (proto == OPEN_TCP) {
        *((uint16_t*)packet) = (uint16_t)*length;   // we do not consider +2 for payload
        packet += 2;
    }

    memcpy(packet, payload, *length);
    encode(packet, *length);

    if (proto == OPEN_TCP)
        *length += 2;   // 2 bytes for TCP length
}

void appendFileName(unsigned char *packet, int dns_length, const unsigned char *file) {
    strcpy(&packet[dns_length], file);
}
