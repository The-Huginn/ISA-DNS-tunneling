/**
 * @file dns_sender.cpp
 * @author xbudin05
 * @brief This file implements dns_sender interface for communicating with dns server via tunneling
 */

#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <err.h>
#include <regex.h>
#include <unistd.h>

#include "dns_sender.h"
#include "utils.h"

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

/*
 *
 * */
u_char *ReadName(unsigned char *reader, unsigned char *buffer, int *count)
{
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char *)malloc(256);

    name[0] = '\0';

    // read the names in 3www6google3com format
    while (*reader != 0)
    {
        if (*reader >= 192)
        {
            offset = (*reader) * 256 + *(reader + 1) - 49152; // 49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; // we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] = *reader;
        }

        reader = reader + 1;

        if (jumped == 0)
        {
            *count = *count + 1; // if we havent jumped to another location then we can count up
        }
    }

    name[p] = '\0'; // string complete
    if (jumped == 1)
    {
        *count = *count + 1; // number of steps we actually moved forward in the packet
    }

    // now convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int)strlen((const char *)name); i++)
    {
        p = name[i];
        for (j = 0; j < (int)p; j++)
        {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; // remove the last dot
    return name;
}

void sendIPv4(int fd, data_cache *data, unsigned char *packet, int length, struct sockaddr_in *dest)
{
    unsigned char buffer[MTU] = {'\0'};

    // dest->sin_addr.s_addr = {data->ipv4}; // fits ipv4 to struct in_addr
    dest->sin_addr.s_addr = inet_addr("192.168.137.179");
    dest->sin_family = AF_INET;
    dest->sin_port = htons(PORT); // set the server port (network byte order)

    // resolvec DNS tunnel receiver if needed by default server
    if (data->ipv4 == DEFAULT_IPV4)
    {
        if (sendto(fd, (char *)packet, length, 0, (const sockaddr *)dest, sizeof(sockaddr_in)) < 0) {
            perror("sendto failed");
        }
        int i = sizeof(dest);
        if (recvfrom(fd, (char *)buffer, MTU, 0, (struct sockaddr *)dest, (socklen_t *)&i) < 0) {
            perror("recvfrom failed");
        }
        dns_header *dns = (dns_header *)buffer;
        unsigned char *reply = &(buffer[length]);

        for (i = 0; i < ntohs(dns->ans_count); i++)
        {
            int stop;
            res_record res;
            res_record *r = &res;
            r->name = ReadName(reply, buffer, &stop);
            printf("Name: %s\n", r->name);
            reply = reply + stop;

            r->resource = (r_data *)(reply);
            reply = reply + sizeof(r_data);

            if (ntohs(r->resource->type) == T_A) // if its an ipv4 address
            {
                r->rdata = (unsigned char *)malloc(ntohs(r->resource->data_len));

                for (int j = 0; j < ntohs(r->resource->data_len); j++)
                {
                    r->rdata[j] = reply[j];
                }

                r->rdata[ntohs(r->resource->data_len)] = '\0';

                reply = reply + ntohs(r->resource->data_len);

                long *p;
                p = (long *)r->rdata;
                sockaddr_in a;
                a.sin_addr.s_addr = (*p); // working without ntohl
                printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
            }
            else
            {
                r->rdata = ReadName(reply, buffer, &stop);
                reply = reply + stop;
            }
        }
    }

    // check the length of input message
    // send UDP with either info for opening a TCP connection for multiple packets
    // or sending UDP packet with payload
    if (sendto(fd, (char *)packet, length, 0, (const sockaddr *)dest, sizeof(sockaddr_in)) < 0) {
        perror("sendto failed");
    }
}

void init_header(dns_header *dns) {
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

void ChangetoDnsNameFormat(unsigned char *dns, data_cache *data)
{
    int lock = 0, i;
    strcat(data->host, ".");

    for (i = 0; i < strlen(data->host); i++)
    {
        if (data->host[i] == '.')
        {
            *dns++ = i - lock + '0';
            for (; lock < i; lock++)
            {
                *dns++ = data->host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

int main(int argc, char *argv[])
{
    data_cache data;
    unsigned char packet[MTU];

    if (read_options(argc, argv, &data) == false)
        return -1;

    // int c;
    // while ((c = fgetc(data.src_file)) != EOF) {
    //     printf("%c", c);
    // }

    int sock, msg_size, i, fd;
    struct sockaddr_in dest;

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        err(1, "socket() failed\n");

    init_header((dns_header *)packet);
    unsigned char *qname = &(packet[HEADER_SIZE]);
    ChangetoDnsNameFormat(qname, &data);

    question *qinfo = (question *)&(packet[HEADER_SIZE + strlen((const char *)qname) + 1]); // +1 for \0
    qinfo->qtype = T_A;                                                                     // we want IP address (in case we need to resolve DNS receiver)
    qinfo->qclass = IN;

    sendIPv4(fd, &data, packet, HEADER_SIZE + strlen((const char *)qname) + 1 + sizeof(question), &dest);

    return 0;
}
// List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;

// Function Prototypes
void ngethostbyname(unsigned char *, int);
unsigned char *ReadName(unsigned char *, unsigned char *, int *);

// DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd : 1;     // recursion desired
    unsigned char tc : 1;     // truncated message
    unsigned char aa : 1;     // authoritive answer
    unsigned char opcode : 4; // purpose of message
    unsigned char qr : 1;     // query/response flag

    unsigned char rcode : 4; // response code
    unsigned char cd : 1;    // checking disabled
    unsigned char ad : 1;    // authenticated data
    unsigned char z : 1;     // its z! reserved
    unsigned char ra : 1;    // recursion available

    unsigned short q_count;    // number of question entries
    unsigned short ans_count;  // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count;  // number of resource entries
};

// Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

// Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

// Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

// Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

/*
 * Perform a DNS query by sending a packet
 * */
void ngethostbyname(unsigned char *host, int query_type)
{
    unsigned char buf[65536], *qname, *reader;
    int i, j, stop, s;

    struct sockaddr_in a;

    struct RES_RECORD answers[20], auth[20], addit[20]; // the replies from the DNS server
    struct sockaddr_in dest;

    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    printf("Resolving %s", host);

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // UDP packet for DNS queries

    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_servers[0]); // dns servers

    // Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;

    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0;     // This is a query
    dns->opcode = 0; // This is a standard query
    dns->aa = 0;     // Not Authoritative
    dns->tc = 0;     // This message is not truncated
    dns->rd = 1;     // Recursion Desired
    dns->ra = 0;     // Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); // we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // point to the query portion
    qname = (unsigned char *)&buf[sizeof(struct DNS_HEADER)];

    qinfo = (struct QUESTION *)&buf[sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1)]; // fill it

    qinfo->qtype = htons(query_type); // type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1);         // its internet (lol)

    printf("\nSending Packet...");
    if (sendto(s, (char *)buf, sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1) + sizeof(struct QUESTION), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        perror("sendto failed");
    }
    printf("Done");

    // Receive the answer
    i = sizeof dest;
    printf("\nReceiving answer...");
    if (recvfrom(s, (char *)buf, 65536, 0, (struct sockaddr *)&dest, (socklen_t *)&i) < 0)
    {
        perror("recvfrom failed");
    }
    printf("Done");

    dns = (struct DNS_HEADER *)buf;

    // move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1) + sizeof(struct QUESTION)];

    printf("\nThe response contains : ");
    printf("\n %d Questions.", ntohs(dns->q_count));
    printf("\n %d Answers.", ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.", ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n", ntohs(dns->add_count));

    // Start reading answers
    stop = 0;

    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        answers[i].name = ReadName(reader, buf, &stop);
        reader = reader + stop;

        answers[i].resource = (struct R_DATA *)(reader);
        reader = reader + sizeof(struct R_DATA);

        if (ntohs(answers[i].resource->type) == 1) // if its an ipv4 address
        {
            answers[i].rdata = (unsigned char *)malloc(ntohs(answers[i].resource->data_len));

            for (j = 0; j < ntohs(answers[i].resource->data_len); j++)
            {
                answers[i].rdata[j] = reader[j];
            }

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader, buf, &stop);
            reader = reader + stop;
        }
    }

    // read authorities
    for (i = 0; i < ntohs(dns->auth_count); i++)
    {
        auth[i].name = ReadName(reader, buf, &stop);
        reader += stop;

        auth[i].resource = (struct R_DATA *)(reader);
        reader += sizeof(struct R_DATA);

        auth[i].rdata = ReadName(reader, buf, &stop);
        reader += stop;
    }

    // read additional
    for (i = 0; i < ntohs(dns->add_count); i++)
    {
        addit[i].name = ReadName(reader, buf, &stop);
        reader += stop;

        addit[i].resource = (struct R_DATA *)(reader);
        reader += sizeof(struct R_DATA);

        if (ntohs(addit[i].resource->type) == 1)
        {
            addit[i].rdata = (unsigned char *)malloc(ntohs(addit[i].resource->data_len));
            for (j = 0; j < ntohs(addit[i].resource->data_len); j++)
                addit[i].rdata[j] = reader[j];

            addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
            reader += ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata = ReadName(reader, buf, &stop);
            reader += stop;
        }
    }

    // print answers
    printf("\nAnswer Records : %d \n", ntohs(dns->ans_count));
    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        printf("Name : %s ", answers[i].name);

        if (ntohs(answers[i].resource->type) == T_A) // IPv4 address
        {
            long *p;
            p = (long *)answers[i].rdata;
            a.sin_addr.s_addr = (*p); // working without ntohl
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }

        if (ntohs(answers[i].resource->type) == 5)
        {
            // Canonical name for an alias
            printf("has alias name : %s", answers[i].rdata);
        }

        printf("\n");
    }

    // print authorities
    printf("\nAuthoritive Records : %d \n", ntohs(dns->auth_count));
    for (i = 0; i < ntohs(dns->auth_count); i++)
    {

        printf("Name : %s ", auth[i].name);
        if (ntohs(auth[i].resource->type) == 2)
        {
            printf("has nameserver : %s", auth[i].rdata);
        }
        printf("\n");
    }

    // print additional resource records
    printf("\nAdditional Records : %d \n", ntohs(dns->add_count));
    for (i = 0; i < ntohs(dns->add_count); i++)
    {
        printf("Name : %s ", addit[i].name);
        if (ntohs(addit[i].resource->type) == 1)
        {
            long *p;
            p = (long *)addit[i].rdata;
            a.sin_addr.s_addr = (*p);
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }
    return;
}
