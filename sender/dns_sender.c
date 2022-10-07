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
#include <signal.h>

#include "dns_sender.h"
#include "utils.h"
#include "../helpers/dnsUtils.h"
#include "dns_sender_events.h"

pid_t child = 0;
int fd;

void killChild(int sig)
{
    child = 0;
    exit(0);
}

void killParent(int sig)
{
    if (child != 0)
        kill(child, SIGKILL);

    close(fd);
    // closing file omitted
    exit(0);
}

/**
 * @returns DNS server address otherwise DEFAULT_NONE if there is a problem getting default DNS server
 */
uint32_t getDNSServer()
{
    FILE *fp;
    char line[200], *p;
    if ((fp = fopen("/etc/resolv.conf", "r")) == NULL)
    {
        fprintf(stderr, "Failed opening /etc/resolv.conf file \n");
        return DEFAULT_NONE;
    }

    while (fgets(line, 200, fp))
    {
        if (line[0] == '#')
        {
            continue;
        }
        if (strncmp(line, "nameserver", 10) == 0)
        {
            p = strtok(line, " ");
            p = strtok(NULL, " ");
            printf("%s", p);
            return inet_addr(p);
        }
    }

    return DEFAULT_NONE;
}

/**
 * @brief Tries to resolve tunnel provided by host name
 */
int resolveTunnel(int fd, data_cache *data, unsigned char *packet, int length, struct sockaddr_in *dest)
{
    in_addr_t dnsServer = (in_addr_t)getDNSServer();
    if (dnsServer == DEFAULT_NONE)
        return false;

    dest->sin_addr.s_addr = dnsServer;
    unsigned char buffer[UDP_MTU] = {'\0'};

    if (sendto(fd, (char *)packet, length, 0, (const struct sockaddr *)dest, sizeof(struct sockaddr_in)) < 0)
    {
        perror("sendto failed");
    }
    int i = sizeof(dest);
    if (recvfrom(fd, (char *)buffer, UDP_MTU, 0, (struct sockaddr *)dest, (socklen_t *)&i) < 0)
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
            return true;
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

    fprintf(stderr, "Unable to resolve host\n");
    return false;
}

int sendIPv4(int fd, data_cache *data, unsigned char *packet, int length, struct sockaddr_in *dest)
{
    dns_sender__on_transfer_init(&dest->sin_addr);

    unsigned char payload[TCP_MTU] = {'\0'};
    dest->sin_addr.s_addr = (in_addr_t)data->ipv4;

    int init = true,
        max_len = UDP_MTU - length, msg_size;

    pid_t pid;

    if ((pid = fork()) == 0)
    { // child
        int msg_size;
        struct sockaddr_in from;
        socklen_t len = sizeof(from);
        fprintf(stderr, "Listening for replies from server\n");
        while ((msg_size = recvfrom(fd, payload, UDP_MTU, 0, (struct sockaddr *)&from, &len)) >= 0)
        {
            unsigned char *reply = readPayload(payload, &msg_size, true);
            fprintf(stderr, "Reply from the server: %s\n", reply);
        }
    }
    else
    { // parent
        child = pid;
    }

    int totalSize = 0;
    int chunk = -1;
    while ((msg_size = fread(payload, 1, max_len, data->src_file)) > 0)
    {
        totalSize += msg_size;
        chunk++;
        // send UDP
        if (init && msg_size < max_len)
        {
            appendMessage(packet, length - (strlen(data->dst_file) + 1), payload, msg_size);
            if (data->encode)
                encode(&packet[length], msg_size);

            dns_sender__on_chunk_encoded(data->dst_file, chunk, data->host);

            if (sendto(fd, packet, length + msg_size, 0, (const struct sockaddr *)dest, sizeof(struct sockaddr_in)) < 0)
            {
                perror("sendto failed");
                return false;
            }

            dns_sender__on_chunk_sent(&dest->sin_addr, data->dst_file, chunk, msg_size);
            return true;
        }
        else if (init)
        { // send one UDP to inform about TCP, still sends name of the file
            init = false;

            ((dns_header *)packet)->q_count = htons(2);

            if (sendto(fd, packet, length, 0, (const struct sockaddr *)dest, sizeof(struct sockaddr_in)) < 0)
            {
                perror("Failed to send message to require TCP connection\n");
                return false;
            }
        }

        if (!switchToTCP(fd, (const struct sockaddr *)dest, packet, length))
            return false;

        // TCP communication
        if (msg_size != max_len)
            ((dns_header *)packet)->q_count = htons(1); // last packet

        appendMessage(packet, length - (strlen(data->dst_file) + 1), payload, msg_size);
        if (data->encode)
                encode(&packet[length], msg_size);

        dns_sender__on_chunk_encoded(data->dst_file, chunk, data->host);

        int i;

        fprintf(stderr, "%d:%d\n", length + msg_size, *((uint16_t *)(&packet[length])));
        if ((i = write(fd, packet, length + msg_size)) == -1)
        {
            perror("unable to write()\n");
            return false;
        }
        else if (i != length + msg_size)
        {
            perror("unable to write() whole message\n");
            return false;
        }
        dns_sender__on_chunk_sent(&dest->sin_addr, data->dst_file, chunk, msg_size);

        max_len = TCP_MTU - length - 2; // -2 for 2 bytes for lenght of TCP
    }

    dns_sender__on_transfer_completed(data->dst_file, totalSize);
    close(fd);

    return true;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, killParent);
    signal(SIGKILL, killChild);

    // Initialization
    data_cache data;
    unsigned char packet[TCP_MTU]; // for UDP communication only UDP_MTU should be used
    int ret = 0;
    struct sockaddr_in dest;

    data.ipv4 = DEFAULT_NONE;
    data.src_file = stdin;
    memset(data.dst_file, '\0', sizeof(data.dst_file));
    memset(data.host, '\0', sizeof(data.host));
    data.encode = true;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(5556); // set the server port (network byte order)

    if (read_options(argc, argv, &data) == false)
        return -1;

    int length = createQuery(packet, data.host);

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        fprintf(stderr, "socket() failed\n");
        return -1;
    }

    if (data.ipv4 == DEFAULT_NONE)
        if (!resolveTunnel(fd, &data, packet, length, &dest)) // resolve custom DNS server
            return -1;

    length = addResource(packet, length);
    appendFileName(packet, length, data.dst_file);
    length += strlen(data.dst_file) + 1;

    // Execution
    if (!sendIPv4(fd, &data, packet, length, &dest))
        ret = -1;

    // Closing resources
    sleep(1); //sleep for 1s
    if (child != 0)
        kill(child, SIGKILL);

    close(fd);
    fclose(data.src_file);

    return ret;
}
