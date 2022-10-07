/**
 * @file dnsUtils.c
 * @author xbudin05
 * @brief This file implements interface in dnsUtils.h
 * @note It was heavily inspired by  Thanks!
 */
#include "dnsUtils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

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

void initHeader(dns_header *dns)
{
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

void ChangetoDnsNameFormat(unsigned char *dns, unsigned char *host)
{
    int lock = 0, i;
    strcat(host, ".");

    for (i = 0; i < strlen(host); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i - lock;
            for (; lock < i; lock++)
            {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

int sendReply(int fd, unsigned char* returnCode, unsigned char* qname, struct sockaddr* client)
{
    unsigned char reply[UDP_MTU];
    initHeader((dns_header *)reply);
    strcpy(&(reply[HEADER_SIZE]), qname);

    question *qinfo = (question *)&(reply[HEADER_SIZE + strlen((const char *)qname) + 1]); // +1 for \0
    qinfo->qtype = ntohs(T_A);                                                             // we want IP address (in case we need to resolve DNS receiver)
    qinfo->qclass = htons(IN);

    unsigned char *rName = &reply[HEADER_SIZE + strlen((const char *)qname) + 1 + sizeof(question)];
    strcpy(rName, qname);
    r_data *rData = (r_data *)(&rName[strlen(qname) + 1]); // move behind the qname
    rData->type = ntohs(T_A);
    rData->_class = ntohs(IN);
    rData->ttl = ntohl(14400);
    rData->data_len = ntohl(sizeof(returnCode));
    strcpy((unsigned char *)&rData[1], returnCode); // move by the r data section

    int msg_len;
    int reply_len = HEADER_SIZE + 2*(strlen(qname) + 1) + sizeof(question) + sizeof(r_data) + strlen(returnCode) + 1;

    if ((msg_len = sendto(fd, reply, reply_len, 0, client, sizeof(struct sockaddr_in))) == -1) {
        fprintf(stderr, "Failed to send reply to client\n");
        return false;
    }
    if (msg_len != reply_len) {
        fprintf(stderr, "Not full message sent to client\n");
        return false;
    }

    return true;
}

int checkProto(dns_header *dns, int proto)
{
    return ntohs(dns->q_count) == proto;
}

void encode(unsigned char* payload, int length)
{
    for (int i = 0; i < length; i++)
    {
        int c = payload[i];
        payload[i] = (c + SEED) % BYTE;
    }
}

void decode(unsigned char* payload, int length)
{
    for (int i = 0; i < length; i++)
    {
        int c = payload[i];
        payload[i] = (c + BYTE - SEED) % BYTE;
    }
}
