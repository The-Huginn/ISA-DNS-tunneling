/**
 * @file utils.c
 * @author xbudin05
 * @brief This file implements interface offered in utils.h
 */

#include "utils.h"

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

void initHeader(dns_header *dns) {
    dns->id = (unsigned short)htons(getpid());

    dns->qr = 0;
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1;

    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;

    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
}

int switchToTCP(int fd, const struct sockaddr *dest, unsigned char *packet, int length) {
    ((dns_header *)packet)->q_count = htons(2);

    if (sendto(fd, (char *)packet, length, 0, dest, sizeof(struct sockaddr_in)) < 0) {
        perror("sendto failed");
        return false;
    }
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

void appendMessage(unsigned char *packet, int dns_length, const unsigned char *payload, int length) {
    memcpy(&packet[dns_length], payload, length);
}