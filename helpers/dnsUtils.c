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
    dns->add_count = htons(1);
}

// Not the best solution to not convert already set name
// we check for a dot and if missing we skip this method
void ChangetoDnsNameFormat(unsigned char *dns, unsigned char *host)
{
    if (strchr(host, '.') == NULL)
        return;

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

int sendReply(int fd, unsigned char* packet, int dns_length, struct sockaddr* client, unsigned char* returnCode, int encoding)
{
    int length = strlen(returnCode), msg_len;
    appendMessage(packet, dns_length, returnCode, length);

    if (encoding)
        encode(&packet[dns_length], length);

    if ((msg_len = sendto(fd, packet, length, 0, client, sizeof(struct sockaddr_in))) == -1) {
        fprintf(stderr, "Failed to send reply to client\n");
        return false;
    }
    if (msg_len != length) {
        fprintf(stderr, "Not full message sent to client\n");
        return false;
    }

    return true;
}

unsigned char *readPayload(unsigned char *packet, int *msg_size, int first)
{
    if (first == false)
        return packet;

    unsigned char* qname = &packet[HEADER_SIZE];
    int length = HEADER_SIZE;
    length += strlen(qname) + 1;

    length += sizeof(question);
    unsigned char *payload = &packet[length];

    payload = &payload[strlen(qname) + 1];
    length += strlen(qname) + 1;
    
    length += sizeof(r_data);

    *msg_size -= getLength(packet, length);

    return &packet[length];
}

int checkProto(dns_header *dns, int proto)
{
    return ntohs(dns->q_count) == proto;
}

int createQuery(unsigned char* packet, unsigned char *host)
{
    initHeader((dns_header *)packet);
    int length = HEADER_SIZE;

    unsigned char *qname = &(packet[HEADER_SIZE]);
    ChangetoDnsNameFormat(qname, host);
    length += strlen((const char *)qname) + 1;

    question *qinfo = (question *)&(packet[length]);
    qinfo->qtype = ntohs(T_A);
    qinfo->qclass = htons(IN);
    length += sizeof(question);

    return length;
}

int addResource(unsigned char* packet, int length)
{
    unsigned char* originalQname = &packet[HEADER_SIZE];
    unsigned char* qname = &(packet[length]);
    strcpy(qname, originalQname);
    length += (strlen((const char*)qname) + 1);

    r_data* rData = (r_data*)&packet[length];
    createRData(rData, 0);
    length += sizeof(r_data);

    return length;
}

void createRData(r_data* rData, int length)
{
    rData->type = ntohs(T_A);
    rData->_class = ntohs(IN);
    rData->ttl = ntohl(14400);
    rData->data_len = ntohs(length);
}

void changeLength(unsigned char* packet, int queryLength, int newLength)
{
    r_data *rData = (r_data*)&packet[queryLength - sizeof(r_data)];
    rData->data_len = ntohs(newLength);
}

int getLength(unsigned char* packet, int queryLength)
{
    r_data *rData = (r_data*)&packet[queryLength - sizeof(r_data)];
    return ntohs(rData->data_len);
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

void appendMessage(unsigned char *packet, int dns_length, const unsigned char *payload, int length)
{
    changeLength(packet, dns_length, length);

    packet = &packet[dns_length];

    memcpy(packet, payload, length);
}

void appendFileName(unsigned char *packet, int dns_length, const unsigned char *file)
{
    strcpy(&packet[dns_length], file);
}
