/**
 * @file dnsHeader.h
 * @author xbudin05
 * @brief This file contains structure for dns packets
 */

#ifndef __DNSHEADER__
#define __DNSHEADER__

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
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    question *ques;
} query;

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

#define T_A 1       // IPv4
#define T_NS 2      // Nameserver
#define  T_SOA 6    // authrority zone
#define T_AAAA 28   // IPv6

#define IN 1        // Class

#define PORT 53             // DNS port

#endif // !__DNSHEADER__