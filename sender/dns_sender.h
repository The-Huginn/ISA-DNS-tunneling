/**
 * @file dns_sender.h
 * @author xbudin05
 * @brief This file contains interface for client side of dns tunneling
 */
#ifndef __DNS_SENDER__
#define __DNS_SENDER__
#include <iomanip>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/**
 * @brief Creates multiple packets if neccessary and sends them to IPv4 address
 * @param address IPv4 address
 * @param char* message
 */
void sendIPv4(uint32_t *address);

/**
 * @brief Creates multiple packets if neccessary and sends them to IPv4 address
 * @param address IPv4 address
 * @param char* message
 */
void sendIPv6(uint16_t *address);

#endif // !__DNS_SENDER__