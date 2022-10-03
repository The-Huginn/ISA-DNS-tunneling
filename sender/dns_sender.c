/**
 * @file dns_sender.cpp
 * @author xbudin05
 * @brief This file implements dns_sender interface for communicating with dns server via tunneling
 *  This file is inspired by https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
 */

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <err.h>
#include <regex.h>

#include "dns_sender.h"
#include "utils.h"
#include "../helpers/dnsUtils.h"

/**
 * @brief Tries to resolve tunnel provided by host name
 */
int resolveTunnel(int fd, data_cache *data, unsigned char *packet, int length, struct sockaddr_in *dest) {
    unsigned char buffer[MTU] = {'\0'};

    if (sendto(fd, (char *)packet, length, 0, (const struct sockaddr *)dest, sizeof(struct sockaddr_in)) < 0)
    {
        perror("sendto failed");
    }
    int i = sizeof(dest);
    if (recvfrom(fd, (char *)buffer, MTU, 0, (struct sockaddr *)dest, (socklen_t *)&i) < 0)
    {
        perror("recvfrom failed");
    }
    dns_header *dns = (dns_header *)buffer;
    unsigned char *reply = &buffer[length];

    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        int stop = 0;
        res_record res;
        res_record *r = &res;

        ReadName(reply, buffer, &stop);
        reply = reply + stop;

        r->resource = (r_data *)(reply);
        reply = reply + sizeof(r_data);

        if (ntohs(r->resource->type) == T_A)
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
            struct sockaddr_in a;
            a.sin_addr.s_addr = (*p); // working without ntohl
            data->ipv4 = a.sin_addr.s_addr;
            dest->sin_addr.s_addr = a.sin_addr.s_addr;
        }
        else
        {
            fprintf(stderr, "DNS server provided NS not an IPv4 address : [");
            r->rdata = ReadName(reply, buffer, &stop);
            reply = reply + stop;
            fprintf(stderr, "%s] Try running again with provided NS using -b\n", r->rdata);
            return false;
        }
    }
    
    dest->sin_addr.s_addr = (in_addr_t)data->ipv4;
    return true;
}

int sendIPv4(int fd, data_cache *data, unsigned char *packet, int length, struct sockaddr_in *dest)
{
    unsigned char buffer[MTU] = {'\0'};
    unsigned char payload[MTU] = {'\0'};

    dest->sin_addr.s_addr = (in_addr_t)data->ipv4;
    dest->sin_family = AF_INET;
    dest->sin_port = htons(PORT); // set the server port (network byte order)

    // resolves DNS tunnel receiver if needed by default server
    // changes destination address
    if (!resolveTunnel(fd, data, packet, length, dest))
        return false;

    // max_len can be without the packet header and destination file name (only for the first packet)
    int init = true, max_len = MTU - length - strlen(data->dst_file), msg_size;
    while ((msg_size = fread(payload, 1, max_len, data->src_file)) > 0)
    {

        // send UDP
        if (init && msg_size < max_len)
        {
            appendFileName(packet, length, data->dst_file);
            appendMessage(packet, length + strlen(data->dst_file) + 1, payload, msg_size);
            if (sendto(fd, (char *)packet, length + msg_size, 0, (const struct sockaddr *)dest, sizeof(struct sockaddr_in)) < 0)
            {
                perror("sendto failed");
                return false;
            }
            return true;
        }
        else if (init)
        { // send one UDP to inform about TCP, still sends name of the file
            init = false;
            appendFileName(packet, length, data->dst_file);
            max_len = MTU - length;

            if (!switchToTCP(fd, (const struct sockaddr *)dest, packet, length))
                return false;
        }

        // TCP communication
        appendMessage(packet, length, payload, msg_size);
        int i;
        if ((i = write(fd, packet, length + msg_size)) == -1) {
            perror("unable to write()\n");
            return false;
        }
        else if (i != length + msg_size) {
            perror("unable to write() whole message\n");
            return false;
        }
    }

    return true;
}

int getDNSServer(data_cache *data)
{
    FILE *fp;
    char line[200] , *p;
    if((fp = fopen("/etc/resolv.conf" , "r")) == NULL) {
        fprintf(stderr, "Failed opening /etc/resolv.conf file \n");
        return false;
    }
     
    while(fgets(line , 200 , fp)) {
        if(line[0] == '#') {
            continue;
        }
        if(strncmp(line , "nameserver" , 10) == 0) {
            p = strtok(line , " ");
            p = strtok(NULL , " ");
            printf("%s", p);
            data->ipv4 = inet_addr(p);
            return true;
        }
    }

    data->ipv4 = DEFAULT_IPV4;
    return true;
}

int main(int argc, char *argv[]) {
    // Initialization
    data_cache data;
    unsigned char packet[MTU];
    int fd, ret = 0;
    struct sockaddr_in dest;

    data.ipv4 = DEFAULT_NONE;
    data.src_file = stdin;
    memset(data.dst_file, '\0', sizeof(data.dst_file));
    memset(data.host, '\0', sizeof(data.host));

    if (read_options(argc, argv, &data) == false)
        return -1;

    if (data.ipv4 == DEFAULT_NONE)
        getDNSServer(&data);

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(stderr, "socket() failed\n");
        return -1;
    }

    initHeader((dns_header *)packet);
    unsigned char *qname = &(packet[HEADER_SIZE]);
    ChangetoDnsNameFormat(qname, data.host);

    question *qinfo = (question *)&(packet[HEADER_SIZE + strlen((const char *)qname) + 1]); // +1 for \0
    qinfo->qtype = ntohs(T_A);                                                              // we want IP address (in case we need to resolve DNS receiver)
    qinfo->qclass = htons(IN);

    // Execution
    if (!sendIPv4(fd, &data, packet, HEADER_SIZE + strlen((const char *)qname) + 1 + sizeof(question), &dest))
        ret = -1;

    // Closing resources
    close(fd);
    fclose(data.src_file);

    return ret;
}
