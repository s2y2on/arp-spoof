#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>


#define ARP_HTYPE_ETH 1
#define ARP_PTYPE_IP 0x0800
#define ARP_HLEN_ETH 6
#define ARP_PLEN_IP 4
#define ARP_OPER_RQ 1
#define ARP_OPER_RP 2
#define SEND_ARP_PERIOD 5

#pragma pack(push, 1)

typedef struct 
{
    uint16_t HTYPE;
    uint16_t PTYPE;
    uint8_t HLEN;
    uint8_t PLEN;
    uint16_t OPER;
    uint8_t sender_h[6];
    uint32_t sender_p;
    uint8_t target_h[6];
    uint32_t target_p;
} arp_header;

typedef struct
{
    uint8_t DMAC[6];
    uint8_t SMAC[6];
    uint16_t ETHTYPE;
    arp_header ARPHDR;
} eth_header;

typedef struct
{
    char dev[16];
    uint32_t sender_IP;
    uint32_t target_IP;
    uint8_t reply_sender[42];
    uint8_t reply_target[42];
} arguments;

#pragma pack(pop)

void usage(void);
void get_ip(char *my_IP_char, char *interface);
void print_ip(char *IP_char);
void get_mac(uint8_t *my_mac, char *interface);
void print_mac(uint8_t *mac);
void arp_request(eth_header *arp, uint8_t *src_mac, uint32_t src_IP, uint32_t dst_IP);
void arp_reply(eth_header *arp, uint8_t *src_mac, uint8_t *dst_mac, uint32_t dst_IP, uint32_t target_IP);
bool get_sendermac(uint8_t *sender_mac, int sender_IP, pcap_t *handel, pcap_pkthdr *hdr, const uint8_t *pkt);
void *arp_send(void *info);
void *block(void *info);
