/**
 * @file utils.h
 * @author xbudin05
 * @brief This file holds utilities for sender.
 */
#ifndef __UTILS__
#define __UTILS__
#include <stdio.h>
#include <arpa/inet.h>

// RFC 1035 4.1.1
typedef struct
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
} dns_header;
 
//Constant sized fields of query structure
typedef struct
{
    unsigned short qtype;
    unsigned short qclass;
} question;
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
typedef struct
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
} r_data;
#pragma pack(pop)
 
//Pointers to resource record contents
typedef struct
{
    unsigned char *name;
    r_data *resource;
    unsigned char *rdata;
} res_record;
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    question *ques;
} query;

#define T_A 1       // IPv4
#define T_NS 2      // Nameserver
#define  T_SOA 6    // authrority zone
#define T_AAAA 28   // IPv6

#define IN 1        // Class

#define PORT 53             // DNS port
#define BUFFER 1024         // buffer length

#define true 1
#define false 0
#define STRING_SIZE 255
#define MTU 1400        // some room for lower layers
#define HEADER_SIZE sizeof(dns_header)
#define DEFAULT_IPV4 134744072  // IPv4 for google.com - 8.8.8.8
#define DEFAULT_IPV6 {8193, 18528, 18528, 0, 0, 0, 0, 25700}// IPv6 for google.com - 2001:4860:4860::6464
typedef struct
{
    uint32_t ipv4 = DEFAULT_IPV4;
    __uint128_t ipv6[8] = DEFAULT_IPV6;
    char host[STRING_SIZE + 1] = {'\0'};     // +1 for '\0'
    char dst_file[STRING_SIZE + 1] = {'\0'}; // +1 for '\0'
    FILE *src_file = stdin;
} data_cache;

#endif // !__UTILS__